#!/usr/bin/env python3
"""Provider-neutral patch catalog option comparison (#23) and read-only OSERA backlog / consumption BOM adapter (#24).

Implements:
- #23: Compare upstream, commercial, and OSERA patch options through a common catalog (`osera-patch-catalog/v1`),
  including JSON/CSV import, member entitlement/approval/repository/pricing overlays (`osera-member-catalog-overlay/v1`),
  delayed availability (`available_from`), commercial vendor-version mapping + fix evidence checks, support dates,
  and side-by-side option comparison with explicit blocked reasons and residual exposure.
- #24: Read-only adapter for `finos-osera-forks/backlog` snapshots (`osera-backlog-snapshot/v1`),
  ingesting `supported-lines.csv`, root and pinned graphs/backlogs, exclusions, per-line status, artifacts,
  `released-with`, unexpected artifacts, and consumption BOMs (`bom`, `parent`, `plugin`, `companion`) while keeping
  member deployment, pinned baseline, and latest-patch resolution strictly distinct.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if "scripts.patch_feeds" in sys.modules:
    from scripts.patch_feeds import (
        ECOSYSTEM_LABELS,
        OSERA_VERSION_RE,
        _derive_minor_line,
        _parse_iso_timestamp,
        extract_osera_maintenance_line,
        parse_purl,
    )
else:
    try:
        from patch_feeds import (
            ECOSYSTEM_LABELS,
            OSERA_VERSION_RE,
            _derive_minor_line,
            _parse_iso_timestamp,
            extract_osera_maintenance_line,
            parse_purl,
        )
    except ImportError:
        from scripts.patch_feeds import (
            ECOSYSTEM_LABELS,
            OSERA_VERSION_RE,
            _derive_minor_line,
            _parse_iso_timestamp,
            extract_osera_maintenance_line,
            parse_purl,
        )

PATCH_CATALOG_SCHEMA_VERSION = "osera-patch-catalog/v1"
MEMBER_CATALOG_OVERLAY_SCHEMA_VERSION = "osera-member-catalog-overlay/v1"
OSERA_BACKLOG_SNAPSHOT_SCHEMA_VERSION = "osera-backlog-snapshot/v1"

VALID_PROVIDER_KINDS = ("upstream", "osera", "commercial", "member")
VALID_RELEASE_STATES = (
    "released",
    "coverage_commitment",
    "future_availability",
    "planned",
    "supported_line",
    "backlog_closed",
    "draft",
    "candidate",
    "withdrawn",
    "superseded",
)
VALID_BACKLOG_ITEM_STATUSES = (
    "open",
    "in_progress",
    "fixed",
    "not_remediable",
    "excluded",
)
VALID_COMPANION_ROLES = ("bom", "parent", "plugin", "companion")

VENDOR_BACKPORT_MARKER_RE = re.compile(
    r"(?i)(?:[.-](?:redhat|rh|nes|herodevs|tuxcare|canonical|ubuntu|deb\d+|el\d+|suse|fips|backport|vendor|commercial)[.-]?\d*)"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_list_field(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if isinstance(value, str) and value.strip():
        return [tok.strip() for tok in re.split(r"[;|,]", value) if tok.strip()]
    return []


def _normalize_coordinate_or_purl(value: Any, default_ecosystem: str = "maven") -> dict[str, Any]:
    """Normalize either a PURL (`pkg:maven/g/a@v`) or `group:artifact@version` / `group:artifact:version` coordinate."""
    raw = str(value or "").strip()
    if not raw:
        return {
            "valid": False,
            "purl": "",
            "ecosystem_type": default_ecosystem,
            "ecosystem": ECOSYSTEM_LABELS.get(default_ecosystem, default_ecosystem),
            "library": "",
            "version": "",
            "error": "Empty coordinate",
        }
    if raw.startswith("pkg:"):
        return parse_purl(raw)

    # Support `group:artifact@version` or `group:artifact:version`
    if "@" in raw and ":" in raw:
        coord_part, ver_part = raw.rsplit("@", 1)
        if ":" in coord_part:
            grp, art = coord_part.split(":", 1)
            return parse_purl(f"pkg:{default_ecosystem}/{grp}/{art}@{ver_part}")
    colon_parts = raw.split(":")
    if len(colon_parts) == 3:
        grp, art, ver = colon_parts
        return parse_purl(f"pkg:{default_ecosystem}/{grp}/{art}@{ver}")
    if len(colon_parts) == 2:
        grp, art = colon_parts
        return {
            "valid": True,
            "purl": f"pkg:{default_ecosystem}/{grp}/{art}",
            "ecosystem_type": default_ecosystem,
            "ecosystem": ECOSYSTEM_LABELS.get(default_ecosystem, default_ecosystem),
            "library": f"{grp}:{art}",
            "version": "",
            "error": None,
        }
    return {
        "valid": False,
        "purl": raw,
        "ecosystem_type": default_ecosystem,
        "ecosystem": ECOSYSTEM_LABELS.get(default_ecosystem, default_ecosystem),
        "library": raw,
        "version": "",
        "error": f"Unrecognized coordinate format: {raw}",
    }


def _build_alias_Normalizer(records: list[dict[str, Any]]) -> Any:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        if x not in parent:
            parent[x] = x
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        # Prefer CVE-* as canonical root over GHSA-* or vendor IDs
        if rb.upper().startswith("CVE-") and not ra.upper().startswith("CVE-"):
            parent[ra] = rb
        else:
            parent[rb] = ra

    for rec in records:
        fixed = _split_list_field(rec.get("fixed_advisories"))
        aliases = _split_list_field(rec.get("aliases"))
        alias_map = rec.get("advisory_aliases")
        if isinstance(alias_map, dict):
            for canonical_id, mapped_list in alias_map.items():
                cid = str(canonical_id).strip()
                for m in _split_list_field(mapped_list):
                    if cid and m:
                        union(cid, m)
        if len(fixed) == 1 and aliases:
            for al in aliases:
                union(fixed[0], al)

    return find


# ============================================================================
# #23 — Provider-Neutral Patch Catalog (JSON & CSV), Member Overlay & Comparison
# ============================================================================


def parse_catalog_csv(
    csv_source: str | Path,
    feed_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse a provider-neutral patch catalog CSV into the canonical `osera-patch-catalog/v1` structure (#23)."""
    cfg = feed_config or {}
    if isinstance(csv_source, Path):
        text = csv_source.read_text(encoding="utf-8")
        default_url = str(csv_source)
    elif isinstance(csv_source, str) and "\n" not in csv_source and Path(csv_source).exists():
        p = Path(csv_source)
        text = p.read_text(encoding="utf-8")
        default_url = str(p)
    else:
        text = str(csv_source or "")
        default_url = "memory://catalog.csv"

    reader = csv.DictReader(io.StringIO(text))
    patches: list[dict[str, Any]] = []
    for idx, row in enumerate(reader):
        if not isinstance(row, dict):
            continue
        runtime_constraints: dict[str, Any] = {}
        if row.get("java_min"):
            runtime_constraints["java_min"] = str(row["java_min"]).strip()
        if row.get("abi_compatible") is not None and str(row.get("abi_compatible")).strip() != "":
            runtime_constraints["abi_compatible"] = str(row["abi_compatible"]).strip().lower() in ("true", "1", "yes")

        support_dates: dict[str, str] = {}
        if row.get("support_start"):
            support_dates["support_start"] = str(row["support_start"]).strip()
        if row.get("support_end") or row.get("eol_at"):
            support_dates["support_end"] = str(row.get("support_end") or row.get("eol_at")).strip()

        vendor_mapping: dict[str, Any] | None = None
        if row.get("upstream_equivalent_version") or row.get("vendor_backport_base"):
            vendor_mapping = {
                "vendor_backport_base": str(row.get("vendor_backport_base") or "").strip(),
                "upstream_equivalent_version": str(row.get("upstream_equivalent_version") or "").strip(),
                "fix_evidence": str(row.get("fix_evidence") or row.get("evidence_url") or "").strip(),
            }

        evidence_links: list[dict[str, str]] = []
        for ev_url in _split_list_field(row.get("evidence_links") or row.get("evidence_url")):
            evidence_links.append({"kind": "advisory_or_attestation", "url": ev_url})

        patches.append(
            {
                "patch_id": str(row.get("patch_id") or f"csv-patch-{idx + 1}").strip(),
                "provider": str(row.get("provider") or cfg.get("provider") or "CatalogCSV").strip(),
                "provider_kind": str(row.get("provider_kind") or cfg.get("provider_kind") or "commercial").strip().lower(),
                "supplier": str(row.get("supplier") or row.get("provider") or cfg.get("provider") or "CatalogCSV").strip(),
                "original_purl": str(row.get("original_purl") or "").strip() or None,
                "replacement_purl": str(row.get("replacement_purl") or "").strip(),
                "applicable_versions": _split_list_field(row.get("applicable_versions")),
                "maintenance_line": str(row.get("maintenance_line") or "").strip() or None,
                "fixed_advisories": _split_list_field(row.get("fixed_advisories")),
                "aliases": _split_list_field(row.get("aliases")),
                "residual_advisories": _split_list_field(row.get("residual_advisories")),
                "runtime_constraints": runtime_constraints,
                "required_companions": _split_list_field(row.get("required_companions")),
                "release_state": str(row.get("release_state") or "released").strip().lower(),
                "available_from": str(row.get("available_from") or "").strip() or None,
                "published_at": str(row.get("published_at") or cfg.get("as_of") or "2026-10-25T00:00:00Z").strip(),
                "artifact_digest": str(row.get("artifact_digest") or "").strip() or None,
                "evidence_links": evidence_links,
                "support_dates": support_dates,
                "vendor_version_mapping": vendor_mapping,
                "withdrawn": str(row.get("withdrawn") or "").strip().lower() in ("true", "1", "yes"),
                "superseded_by": str(row.get("superseded_by") or "").strip() or None,
            }
        )

    return {
        "schema_version": PATCH_CATALOG_SCHEMA_VERSION,
        "feed_id": str(cfg.get("feed_id") or "csv-catalog"),
        "provider": str(cfg.get("provider") or "CatalogCSV"),
        "provider_kind": str(cfg.get("provider_kind") or "commercial"),
        "source_url": str(cfg.get("source_url") or default_url),
        "snapshot_version": str(cfg.get("snapshot_version") or "1.0"),
        "as_of": str(cfg.get("as_of") or "2026-10-25T00:00:00Z"),
        "patches": patches,
    }


def normalize_common_catalog_entry(
    raw: dict[str, Any],
    feed_meta: dict[str, Any] | None = None,
    member_overlay: dict[str, Any] | None = None,
    evaluation_time: str | None = None,
) -> dict[str, Any]:
    """Normalize and validate a single patch option under `osera-patch-catalog/v1` (#23).

    Enforces #23 invariants:
    - Coverage commitments without a release (`coverage_commitment` / `supported_line` / `planned`),
      future availability (`available_from > evaluation_time`), expired entitlements, unentitled commercial
      options, and withdrawn/superseded artifacts CANNOT become `ready` (`ready=False` with explicit `blocked_reasons`).
    - No entitlement, price, or commercial coverage is ever inferred from marketing or the existence of a fork.
    - Commercial backports require explicit `vendor_version_mapping` and `fix_evidence` (`evidence_links` or
      `vendor_version_mapping.fix_evidence`) rather than upstream version string comparison alone.
    """
    meta = feed_meta or {}
    eval_ts = _parse_iso_timestamp(evaluation_time) or _now_iso()

    replacement_purl = str(raw.get("replacement_purl") or raw.get("target") or "").strip()
    parsed_rep = parse_purl(replacement_purl)
    original_purl = str(raw.get("original_purl") or raw.get("source_package") or "").strip()
    parsed_orig = parse_purl(original_purl) if original_purl.startswith("pkg:") else None

    osera_line = extract_osera_maintenance_line(parsed_rep["version"]) if parsed_rep["valid"] else None
    provider = str(raw.get("provider") or meta.get("provider") or ("OSERA" if osera_line else "Upstream")).strip()
    provider_kind = str(
        raw.get("provider_kind")
        or meta.get("provider_kind")
        or ("osera" if osera_line else "upstream")
    ).strip().lower()
    if provider_kind not in VALID_PROVIDER_KINDS:
        provider_kind = "commercial" if provider.lower() not in ("upstream", "osera") else provider.lower()

    release_state = str(raw.get("release_state") or raw.get("state") or "released").strip().lower()
    withdrawn = bool(raw.get("withdrawn", False)) or release_state == "withdrawn"
    if withdrawn:
        release_state = "withdrawn"
    superseded_by = str(raw.get("superseded_by") or "").strip() or None
    if superseded_by and release_state == "released":
        release_state = "superseded"

    applicable_versions = _split_list_field(raw.get("applicable_versions") or raw.get("source_versions"))
    if osera_line and osera_line["base_version"] not in applicable_versions:
        applicable_versions.append(osera_line["base_version"])

    fixed_advisories = _split_list_field(raw.get("fixed_advisories") or raw.get("advisories"))
    aliases = _split_list_field(raw.get("aliases"))
    residual_advisories = _split_list_field(raw.get("residual_advisories"))
    required_companions = _split_list_field(raw.get("required_companions") or raw.get("companions"))

    published_at = _parse_iso_timestamp(raw.get("published_at") or meta.get("last_refresh") or meta.get("as_of"))
    available_from = _parse_iso_timestamp(raw.get("available_from"))
    support_dates_raw = raw.get("support_dates") if isinstance(raw.get("support_dates"), dict) else {}
    support_start = _parse_iso_timestamp(support_dates_raw.get("support_start") or raw.get("support_start"))
    support_end = _parse_iso_timestamp(
        support_dates_raw.get("support_end") or support_dates_raw.get("eol_at") or raw.get("support_end")
    )

    evidence_links = raw.get("evidence_links") if isinstance(raw.get("evidence_links"), list) else []
    vendor_mapping = raw.get("vendor_version_mapping") if isinstance(raw.get("vendor_version_mapping"), dict) else None

    # Member overlay lookup: NEVER infer entitlement, pricing, or commercial coverage from marketing or fork existence!
    patch_id = str(raw.get("patch_id") or raw.get("id") or f"{provider}:{replacement_purl}").strip()
    lib_coord = (
        parsed_orig["library"]
        if (parsed_orig and parsed_orig.get("library"))
        else (parsed_rep["library"] if parsed_rep["valid"] else "")
    )
    entitlement_status = "not_required" if provider_kind in ("upstream", "osera") else "unentitled"
    approval_status = "approved" if provider_kind == "upstream" else "pending"
    internal_repo_url: str | None = None
    pricing_model: dict[str, Any] | None = None
    entitlement_expires_at: str | None = None

    if isinstance(member_overlay, dict):
        entitlements = member_overlay.get("entitlements") if isinstance(member_overlay.get("entitlements"), list) else []
        matched_ent = None
        for ent in entitlements:
            if not isinstance(ent, dict):
                continue
            ent_patch_id = str(ent.get("patch_id") or "").strip()
            ent_provider = str(ent.get("provider") or "").strip()
            ent_lib = str(ent.get("library") or ent.get("package") or "*").strip()
            if ent_patch_id:
                if ent_patch_id == patch_id:
                    matched_ent = ent
                    break
                continue
            if ent_provider and ent_provider.lower() == provider.lower() and ent_lib in ("*", lib_coord):
                matched_ent = ent
                break

        if matched_ent is not None:
            raw_ent_status = str(matched_ent.get("status") or "entitled").strip().lower()
            entitlement_expires_at = _parse_iso_timestamp(matched_ent.get("expires_at"))
            if entitlement_expires_at and entitlement_expires_at < eval_ts:
                entitlement_status = "expired"
            elif raw_ent_status in ("entitled", "active"):
                entitlement_status = "entitled"
            elif raw_ent_status in ("expired", "unentitled", "none", "denied"):
                entitlement_status = "expired" if raw_ent_status == "expired" else "unentitled"
            else:
                entitlement_status = "unknown"

            if matched_ent.get("approval_status"):
                approval_status = str(matched_ent["approval_status"]).strip().lower()
            if matched_ent.get("internal_repository_url"):
                internal_repo_url = str(matched_ent["internal_repository_url"]).strip()
            if isinstance(matched_ent.get("pricing"), dict):
                pricing_model = copy.deepcopy(matched_ent["pricing"])

        approvals = member_overlay.get("approvals") if isinstance(member_overlay.get("approvals"), dict) else {}
        if patch_id in approvals:
            approval_status = str(approvals[patch_id]).strip().lower()
        elif provider in approvals and approval_status == "pending":
            approval_status = str(approvals[provider]).strip().lower()

        routing = member_overlay.get("repository_routing") if isinstance(member_overlay.get("repository_routing"), dict) else {}
        if not internal_repo_url and provider in routing:
            internal_repo_url = str(routing[provider]).strip()

    blocked_reasons: list[str] = []
    if not parsed_rep["valid"]:
        blocked_reasons.append("invalid_replacement_purl")
    if withdrawn or release_state == "withdrawn":
        blocked_reasons.append("withdrawn_artifact")
    if release_state == "superseded":
        blocked_reasons.append("superseded_artifact")
    if release_state in ("coverage_commitment", "supported_line", "backlog_closed", "planned", "draft", "candidate"):
        blocked_reasons.append("coverage_commitment_without_release")
    if release_state == "future_availability" or (available_from and available_from > eval_ts):
        blocked_reasons.append("future_delayed_availability")
    if support_end and support_end < eval_ts:
        blocked_reasons.append("support_window_expired")
    if provider_kind == "commercial":
        if entitlement_status == "expired":
            blocked_reasons.append("expired_entitlement")
        elif entitlement_status != "entitled":
            blocked_reasons.append("missing_commercial_entitlement")
        # Commercial backports require explicit vendor-version mapping and fix evidence
        has_mapping = isinstance(vendor_mapping, dict) and bool(
            vendor_mapping.get("vendor_backport_base") or vendor_mapping.get("upstream_equivalent_version")
        )
        has_fix_evidence = bool(evidence_links) or bool(
            isinstance(vendor_mapping, dict) and vendor_mapping.get("fix_evidence")
        )
        if not has_mapping or not has_fix_evidence:
            blocked_reasons.append("missing_commercial_vendor_mapping_or_fix_evidence")
    elif entitlement_status == "expired":
        blocked_reasons.append("expired_entitlement")

    if approval_status in ("rejected", "blocked"):
        blocked_reasons.append("member_policy_rejected")

    if not fixed_advisories:
        blocked_reasons.append("no_fixed_advisories_declared")

    ready = len(blocked_reasons) == 0 and release_state == "released"

    return {
        "patch_id": patch_id,
        "feed_id": str(raw.get("feed_id") or meta.get("feed_id") or "catalog"),
        "provider": provider,
        "provider_kind": provider_kind,
        "supplier": str(raw.get("supplier") or provider),
        "ecosystem_type": parsed_rep["ecosystem_type"],
        "ecosystem": parsed_rep["ecosystem"],
        "library": lib_coord,
        "original_purl": original_purl or (f"pkg:{parsed_rep['ecosystem_type']}/{lib_coord.replace(':', '/')}" if lib_coord else None),
        "replacement_purl": parsed_rep["purl"] if parsed_rep["valid"] else replacement_purl,
        "replacement_version": parsed_rep["version"],
        "applicable_versions": applicable_versions,
        "maintenance_line": str(
            raw.get("maintenance_line")
            or (osera_line["maintenance_line"] if osera_line else _derive_minor_line(parsed_rep["version"]))
        ),
        "fixed_advisories": fixed_advisories,
        "aliases": aliases,
        "advisory_aliases": raw.get("advisory_aliases") if isinstance(raw.get("advisory_aliases"), dict) else {},
        "residual_advisories": residual_advisories,
        "runtime_constraints": copy.deepcopy(raw.get("runtime_constraints")) if isinstance(raw.get("runtime_constraints"), dict) else {},
        "required_companions": required_companions,
        "release_state": release_state,
        "available_from": available_from,
        "published_at": published_at,
        "evidence_freshness": published_at or "unknown",
        "artifact_digest": raw.get("artifact_digest"),
        "evidence_links": copy.deepcopy(evidence_links),
        "support_dates": {
            "support_start": support_start,
            "support_end": support_end,
        },
        "vendor_version_mapping": copy.deepcopy(vendor_mapping) if vendor_mapping else None,
        "withdrawn": withdrawn,
        "superseded_by": superseded_by,
        "entitlement_status": entitlement_status,
        "entitlement_expires_at": entitlement_expires_at,
        "approval_status": approval_status,
        "internal_repository_url": internal_repo_url,
        "pricing": pricing_model,
        "ready": ready,
        "blocked_reasons": blocked_reasons,
    }


def compare_patch_options(
    component: dict[str, Any],
    catalog_sources: list[dict[str, Any]],
    member_overlay: dict[str, Any] | None = None,
    evaluation_time: str | None = None,
) -> dict[str, Any]:
    """Compare upstream, commercial, and OSERA patch options for a component observation (#23).

    Returns normalized options clearly marked by provenance (`upstream`, `osera`, `commercial`),
    with source version, exact target, evidence freshness, remaining vulnerabilities, runtime constraints,
    entitlement/approval status, and explicit `blocked_reasons` without conflating provider-specific artifacts.
    """
    eval_ts = _parse_iso_timestamp(evaluation_time) or _now_iso()
    comp_purl_raw = str(component.get("purl") or "").strip()
    if comp_purl_raw:
        comp_parsed = parse_purl(comp_purl_raw)
    else:
        eco = str(component.get("ecosystem_type") or component.get("namespace") or "maven").strip().lower()
        lib = str(component.get("library") or "").strip()
        if not lib and component.get("meta") and component.get("proj"):
            lib = f"{component['meta']}:{component['proj']}"
        ver = str(component.get("version") or component.get("release") or "").strip()
        comp_parsed = parse_purl(f"pkg:{eco}/{lib.replace(':', '/')}@{ver}")

    source_version = comp_parsed["version"]
    library_coord = comp_parsed["library"]
    ecosystem_type = comp_parsed["ecosystem_type"]

    # Collect all raw patches across provided catalog sources
    raw_entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for src in catalog_sources:
        if not isinstance(src, dict):
            continue
        doc = src.get("document") if isinstance(src.get("document"), dict) else src
        cfg = src.get("config") if isinstance(src.get("config"), dict) else src
        if bool(cfg.get("enabled", doc.get("enabled", True))) is False:
            continue
        meta = {
            "feed_id": cfg.get("feed_id") or doc.get("feed_id") or doc.get("id") or "catalog",
            "provider": cfg.get("provider") or doc.get("provider"),
            "provider_kind": cfg.get("provider_kind") or doc.get("provider_kind"),
            "last_refresh": cfg.get("last_refresh") or doc.get("as_of") or doc.get("generated_at") or doc.get("timestamp"),
        }
        for p in doc.get("patches") or []:
            if isinstance(p, dict):
                raw_entries.append((p, meta))

    normalized_all = [
        normalize_common_catalog_entry(p, meta, member_overlay=member_overlay, evaluation_time=eval_ts)
        for p, meta in raw_entries
    ]
    canonical_adv = _build_alias_Normalizer(normalized_all)

    observed_advisories_raw = _split_list_field(
        component.get("advisories")
        or component.get("cves")
        or [c.get("cve_id") for c in (component.get("cve_list") or []) if isinstance(c, dict)]
    )
    observed_canonical = [canonical_adv(a) for a in observed_advisories_raw]

    matching_options: list[dict[str, Any]] = []
    seen_option_identities: set[tuple[str, str, str]] = set()

    for opt in normalized_all:
        if opt["ecosystem_type"] != ecosystem_type or opt["library"] != library_coord:
            continue

        # Keep distinct provider artifacts separate (`(provider, replacement_purl, patch_id)`)
        opt_key = (opt["provider"], opt["replacement_purl"], opt["patch_id"])
        if opt_key in seen_option_identities:
            continue
        seen_option_identities.add(opt_key)

        option_copy = copy.deepcopy(opt)
        option_copy["source_version"] = source_version
        option_copy["exact_target"] = opt["replacement_purl"]

        # Check source-version applicability
        applicable = source_version in opt["applicable_versions"]
        if (
            not applicable
            and opt["provider_kind"] == "commercial"
            and isinstance(opt.get("vendor_version_mapping"), dict)
            and opt["vendor_version_mapping"].get("vendor_backport_base") == source_version
        ):
            applicable = True

        if not applicable and "source_version_not_in_applicable_versions" not in option_copy["blocked_reasons"]:
            option_copy["blocked_reasons"].append("source_version_not_in_applicable_versions")
            option_copy["ready"] = False

        fixed_canonical = {canonical_adv(a) for a in opt["fixed_advisories"] + opt["aliases"]}
        option_copy["normalized_fixed_advisories"] = sorted(fixed_canonical)

        addressed = [
            raw_adv
            for raw_adv, can_adv in zip(observed_advisories_raw, observed_canonical)
            if can_adv in fixed_canonical
        ]
        remaining_from_observed = [
            raw_adv
            for raw_adv, can_adv in zip(observed_advisories_raw, observed_canonical)
            if can_adv not in fixed_canonical
        ]
        explicit_residuals = [
            r for r in opt["residual_advisories"] if canonical_adv(r) not in {canonical_adv(x) for x in remaining_from_observed}
        ]
        remaining_vulnerabilities = remaining_from_observed + explicit_residuals

        option_copy["addressed_vulnerabilities"] = addressed
        option_copy["remaining_vulnerabilities"] = remaining_vulnerabilities
        option_copy["eligibility_state"] = (
            "ready"
            if option_copy["ready"]
            else ("blocked" if option_copy["blocked_reasons"] else "review_required")
        )
        matching_options.append(option_copy)

    # Deterministic sort: ready options first, then fewer remaining vulnerabilities, then provider_kind (osera, upstream, commercial)
    kind_rank = {"osera": 0, "upstream": 1, "commercial": 2, "member": 3}
    matching_options.sort(
        key=lambda o: (
            0 if o["ready"] else 1,
            len(o["remaining_vulnerabilities"]),
            kind_rank.get(o["provider_kind"], 9),
            o["replacement_purl"],
        )
    )

    return {
        "schema_version": PATCH_CATALOG_SCHEMA_VERSION,
        "evaluated_at": eval_ts,
        "component": {
            "ecosystem_type": ecosystem_type,
            "library": library_coord,
            "source_version": source_version,
            "observed_advisories": observed_advisories_raw,
        },
        "options": matching_options,
        "ready_options": [o for o in matching_options if o["ready"]],
        "blocked_options": [o for o in matching_options if not o["ready"]],
        "providers_represented": sorted({o["provider_kind"] for o in matching_options}),
    }


# ============================================================================
# #24 — Read-Only OSERA Backlog, Line Baselines & Consumption BOMs Adapter
# ============================================================================


def parse_supported_lines_csv(csv_source: str | Path | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse `supported-lines.csv` from `finos-osera-forks/backlog` (#24)."""
    if isinstance(csv_source, list):
        raw_rows = [r for r in csv_source if isinstance(r, dict)]
    else:
        if isinstance(csv_source, Path):
            text = csv_source.read_text(encoding="utf-8")
        elif isinstance(csv_source, str) and "\n" not in csv_source and Path(csv_source).exists():
            text = Path(csv_source).read_text(encoding="utf-8")
        else:
            text = str(csv_source or "")
        raw_rows = list(csv.DictReader(io.StringIO(text)))

    lines: list[dict[str, Any]] = []
    for idx, row in enumerate(raw_rows):
        ecosystem = str(row.get("ecosystem") or "maven").strip().lower()
        group_id = str(row.get("group_id") or row.get("group") or "").strip()
        artifact_id = str(row.get("artifact_id") or row.get("artifact") or "").strip()
        coord = str(row.get("coordinate") or row.get("library") or "").strip()
        if not coord and group_id and artifact_id:
            coord = f"{group_id}:{artifact_id}"
        line_id = str(row.get("line_id") or row.get("line") or row.get("maintenance_line") or "").strip()
        pinned_baseline = str(row.get("pinned_baseline") or row.get("baseline_version") or "").strip()
        latest_patch = str(row.get("latest_patch") or row.get("latest_version") or "").strip()
        consume_coord = str(row.get("consume") or row.get("consume_coordinate") or "").strip()
        line_status = str(row.get("status") or row.get("line_status") or "active").strip().lower()
        consumption_bom = str(row.get("consumption_bom") or row.get("bom_coordinate") or "").strip()

        lines.append(
            {
                "row_index": idx,
                "line_id": line_id or f"{coord}:{ _derive_minor_line(pinned_baseline or latest_patch) }",
                "ecosystem_type": ecosystem,
                "library": coord,
                "maintenance_line": str(row.get("maintenance_line") or _derive_minor_line(pinned_baseline or latest_patch)),
                "pinned_baseline": pinned_baseline,
                "latest_patch": latest_patch,
                "consume_coordinate": consume_coord,
                "consumption_bom": consumption_bom or None,
                "line_status": line_status,
            }
        )
    return lines


def ingest_osera_backlog_snapshot(snapshot: dict[str, Any] | Path) -> dict[str, Any]:
    """Read-only adapter for a consistent commit/tag snapshot of `finos-osera-forks/backlog` (#24).

    Validates and normalizes:
    - `supported-lines.csv` (`supported_lines`)
    - `root` and `pinned` graphs / backlog items (`backlog_items`)
    - `exclusions` (`exclusions`)
    - `per-line status` (`line_statuses`)
    - `artifacts`, `released_with`, `unexpected_artifacts`, and `consumption_boms`
    - Preserves `source_commit`, `schema_version`, `view`, `book_version`, and timestamps.
    - Surfaces actionable `data_quality_issues` for inconsistent snapshots, empty `consume` coordinates,
      missing `fixed_by` on `fixed` items, and `unexpected_artifacts`.
    - Models companion BOMs, parents, and plugins with explicit roles without counting each companion
      as a separate vulnerability fix.
    """
    if isinstance(snapshot, Path):
        payload = json.loads(snapshot.read_text(encoding="utf-8"))
    else:
        payload = copy.deepcopy(snapshot)

    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else payload
    source_repo = str(meta.get("source_repo") or "https://github.com/finos-osera-forks/backlog").strip()
    source_commit = str(meta.get("source_commit") or meta.get("commit_sha") or "").strip()
    source_tag = str(meta.get("source_tag") or meta.get("tag") or "").strip() or None
    book_version = str(meta.get("book_version") or meta.get("version") or "unknown").strip()
    view = str(meta.get("view") or "pinned_and_latest").strip()
    commit_timestamp = _parse_iso_timestamp(meta.get("commit_timestamp") or meta.get("timestamp"))
    ingested_at = _parse_iso_timestamp(meta.get("ingested_at")) or _now_iso()

    data_quality_issues: list[dict[str, Any]] = []

    if not source_commit:
        data_quality_issues.append(
            {
                "kind": "missing_source_commit",
                "severity": "error",
                "message": "Backlog snapshot is missing source_commit SHA.",
            }
        )
    if not commit_timestamp:
        data_quality_issues.append(
            {
                "kind": "missing_snapshot_timestamp",
                "severity": "warning",
                "message": "Backlog snapshot is missing commit_timestamp.",
            }
        )

    # Check cross-artifact snapshot consistency (commit SHA & book_version across views/files)
    component_commits = meta.get("component_commits") if isinstance(meta.get("component_commits"), dict) else {}
    for file_key, file_sha in component_commits.items():
        if source_commit and str(file_sha).strip() and str(file_sha).strip() != source_commit:
            data_quality_issues.append(
                {
                    "kind": "inconsistent_snapshot",
                    "severity": "error",
                    "artifact": file_key,
                    "expected_commit": source_commit,
                    "observed_commit": str(file_sha).strip(),
                    "message": f"Snapshot inconsistency: {file_key} is at commit {file_sha}, expected {source_commit}.",
                }
            )

    supported_lines = parse_supported_lines_csv(payload.get("supported_lines_csv") or payload.get("supported_lines") or [])
    lines_by_id: dict[str, dict[str, Any]] = {}
    lines_by_coord: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for line in supported_lines:
        if not line["consume_coordinate"] and line["line_status"] in ("active", "released", "supported"):
            data_quality_issues.append(
                {
                    "kind": "empty_consume_coordinate",
                    "severity": "warning",
                    "line_id": line["line_id"],
                    "library": line["library"],
                    "message": f"Supported line {line['line_id']} has an empty consume coordinate; cannot grant direct consumption availability.",
                }
            )
        lines_by_id[line["line_id"]] = line
        lines_by_coord.setdefault((line["ecosystem_type"], line["library"]), []).append(line)

    # Process exclusions with a separate contract (exclusions are scope changes, NEVER remediation!)
    raw_exclusions = payload.get("exclusions") if isinstance(payload.get("exclusions"), list) else []
    exclusions: list[dict[str, Any]] = []
    excluded_keys: set[tuple[str, str]] = set()
    for idx, exc in enumerate(raw_exclusions):
        if not isinstance(exc, dict):
            continue
        eco = str(exc.get("ecosystem") or "maven").strip().lower()
        lib = str(exc.get("library") or exc.get("coordinate") or "").strip()
        adv = str(exc.get("advisory_id") or exc.get("cve_id") or "").strip()
        reason = str(exc.get("reason") or exc.get("rationale") or "").strip()
        approved_by = str(exc.get("approved_by") or "").strip()
        if not lib or not reason:
            data_quality_issues.append(
                {
                    "kind": "invalid_exclusion_record",
                    "severity": "warning",
                    "index": idx,
                    "message": f"Exclusion record[{idx}] is missing required library coordinate or reason.",
                }
            )
            continue
        exclusions.append(
            {
                "ecosystem_type": eco,
                "library": lib,
                "maintenance_line": str(exc.get("maintenance_line") or "*").strip(),
                "advisory_id": adv or "*",
                "status": "excluded",
                "counts_as_remediation": False,
                "reason": reason,
                "approved_by": approved_by or None,
                "excluded_at": _parse_iso_timestamp(exc.get("excluded_at")) or commit_timestamp,
            }
        )
        excluded_keys.add((lib, adv or "*"))

    # Process consumption BOMs and companion artifacts (`bom`, `parent`, `plugin`, `companion`)
    raw_boms = payload.get("consumption_boms") if isinstance(payload.get("consumption_boms"), list) else []
    consumption_boms: list[dict[str, Any]] = []
    boms_by_line_id: dict[str, dict[str, Any]] = {}
    for bom in raw_boms:
        if not isinstance(bom, dict):
            continue
        line_id = str(bom.get("line_id") or "").strip()
        bom_coord = str(bom.get("bom_coordinate") or bom.get("purl") or "").strip()
        norm_bom = _normalize_coordinate_or_purl(bom_coord)
        members: list[dict[str, Any]] = []
        primary_fix_coords: list[str] = []
        companion_only_coords: list[str] = []

        for mem in bom.get("members") or bom.get("artifacts") or []:
            if not isinstance(mem, dict):
                continue
            m_coord = str(mem.get("coordinate") or mem.get("purl") or "").strip()
            m_norm = _normalize_coordinate_or_purl(m_coord)
            role = str(mem.get("role") or "companion").strip().lower()
            if role not in ("primary", *VALID_COMPANION_ROLES):
                role = "companion"
            counts_as_separate_fix = bool(role == "primary")
            if role == "primary":
                primary_fix_coords.append(m_norm["purl"])
            else:
                companion_only_coords.append(m_norm["purl"])
            members.append(
                {
                    "purl": m_norm["purl"],
                    "library": m_norm["library"],
                    "version": m_norm["version"],
                    "role": role,
                    "counts_as_separate_vulnerability_fix": counts_as_separate_fix,
                }
            )

        bom_record = {
            "line_id": line_id,
            "bom_purl": norm_bom["purl"],
            "bom_library": norm_bom["library"],
            "bom_version": norm_bom["version"],
            "released_with": _split_list_field(bom.get("released_with")),
            "members": members,
            "primary_fix_artifacts": primary_fix_coords,
            "companion_artifacts": companion_only_coords,
        }
        consumption_boms.append(bom_record)
        if line_id:
            boms_by_line_id[line_id] = bom_record

    # Surface unexpected artifacts explicitly
    raw_unexpected = payload.get("unexpected_artifacts") if isinstance(payload.get("unexpected_artifacts"), list) else []
    unexpected_artifacts: list[dict[str, Any]] = []
    for ua in raw_unexpected:
        coord = str(ua.get("coordinate") or ua.get("purl") or "") if isinstance(ua, dict) else str(ua or "")
        reason = str(ua.get("reason") or "Artifact version or coordinate not declared in supported-lines.csv or release BOM") if isinstance(ua, dict) else "Unexpected artifact in release output"
        norm_ua = _normalize_coordinate_or_purl(coord)
        unexpected_artifacts.append(
            {
                "purl": norm_ua["purl"] or coord,
                "library": norm_ua["library"],
                "version": norm_ua["version"],
                "reason": reason,
            }
        )
        data_quality_issues.append(
            {
                "kind": "unexpected_artifact_version",
                "severity": "warning",
                "artifact": norm_ua["purl"] or coord,
                "message": f"Unexpected artifact observed in OSERA release output: {norm_ua['purl'] or coord} ({reason}).",
            }
        )

    # Process backlog items across `open`, `in_progress`, `fixed`, `not_remediable`, `excluded`
    raw_items = payload.get("backlog_items") if isinstance(payload.get("backlog_items"), list) else []
    alias_norm = _build_alias_Normalizer(
        [
            {
                "fixed_advisories": [i.get("advisory_id") or i.get("cve_id")],
                "aliases": i.get("aliases") or [],
            }
            for i in raw_items
            if isinstance(i, dict)
        ]
    )

    backlog_items: list[dict[str, Any]] = []
    seen_item_keys: set[tuple[str, str, str]] = set()

    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            continue
        eco = str(item.get("ecosystem") or "maven").strip().lower()
        lib = str(item.get("library") or item.get("coordinate") or "").strip()
        line_id = str(item.get("line_id") or "").strip()
        adv_raw = str(item.get("advisory_id") or item.get("cve_id") or "").strip()
        aliases = _split_list_field(item.get("aliases"))
        canonical_adv = alias_norm(adv_raw) if adv_raw else ""
        raw_status = str(item.get("status") or "open").strip().lower().replace("-", "_")
        if (lib, adv_raw) in excluded_keys or (lib, "*") in excluded_keys:
            raw_status = "excluded"
        if raw_status not in VALID_BACKLOG_ITEM_STATUSES:
            raw_status = "open"

        fixed_by_raw = str(item.get("fixed_by") or "").strip()
        fixed_by_norm = _normalize_coordinate_or_purl(fixed_by_raw, eco) if fixed_by_raw else None
        line_info = lines_by_id.get(line_id) or (lines_by_coord.get((eco, lib), [None])[0])
        consume_coord = str(
            item.get("consume_coordinate")
            or (line_info.get("consume_coordinate") if isinstance(line_info, dict) else "")
            or ""
        ).strip()

        dedup_key = (lib, line_id or _derive_minor_line(str(item.get("baseline_version") or "")), canonical_adv)
        if dedup_key in seen_item_keys:
            continue
        seen_item_keys.add(dedup_key)

        availability_granted = False
        quality_state = "valid"
        if raw_status == "fixed":
            if not fixed_by_raw or not (fixed_by_norm and fixed_by_norm["valid"] and fixed_by_norm["version"]):
                quality_state = "missing_fixed_by_evidence"
                data_quality_issues.append(
                    {
                        "kind": "missing_fixed_by_on_fixed_item",
                        "severity": "error",
                        "library": lib,
                        "advisory_id": canonical_adv,
                        "line_id": line_id,
                        "message": f"Backlog item {lib} ({canonical_adv}) has status='fixed' but is missing a valid fixed_by coordinate.",
                    }
                )
            elif not consume_coord:
                quality_state = "empty_consume_coordinate"
                data_quality_issues.append(
                    {
                        "kind": "fixed_item_empty_consume_coordinate",
                        "severity": "warning",
                        "library": lib,
                        "advisory_id": canonical_adv,
                        "line_id": line_id,
                        "message": f"Backlog item {lib} ({canonical_adv}) is marked fixed by {fixed_by_raw} but has an empty consume coordinate.",
                    }
                )
            else:
                availability_granted = True

        backlog_items.append(
            {
                "item_id": str(item.get("item_id") or f"backlog-{idx + 1}"),
                "line_id": line_id or (line_info["line_id"] if isinstance(line_info, dict) else f"{lib}:default"),
                "ecosystem_type": eco,
                "library": lib,
                "maintenance_line": str(
                    item.get("maintenance_line")
                    or (line_info["maintenance_line"] if isinstance(line_info, dict) else "")
                ),
                "pinned_baseline": str(
                    item.get("pinned_baseline")
                    or (line_info["pinned_baseline"] if isinstance(line_info, dict) else "")
                ),
                "latest_patch": str(
                    item.get("latest_patch")
                    or (line_info["latest_patch"] if isinstance(line_info, dict) else "")
                ),
                "advisory_id": canonical_adv,
                "raw_advisory_id": adv_raw,
                "aliases": sorted(set([adv_raw, *aliases]) - {canonical_adv}),
                "status": raw_status,
                "fixed_by": fixed_by_norm["purl"] if (fixed_by_norm and fixed_by_norm["valid"]) else None,
                "fixed_by_version": fixed_by_norm["version"] if (fixed_by_norm and fixed_by_norm["valid"]) else None,
                "consume_coordinate": consume_coord or None,
                "released_with": _split_list_field(item.get("released_with")),
                "availability_granted": availability_granted,
                "data_quality_state": quality_state,
            }
        )

    # Summarize per-line status (exposing partial line coverage explicitly)
    line_summaries: list[dict[str, Any]] = []
    for line in supported_lines:
        lid = line["line_id"]
        items_for_line = [it for it in backlog_items if it["line_id"] == lid]
        avail_fixes = [it for it in items_for_line if it["availability_granted"]]
        unresolved_items = [
            it for it in items_for_line if it["status"] in ("open", "in_progress", "not_remediable") or not it["availability_granted"]
        ]
        excluded_items = [it for it in items_for_line if it["status"] == "excluded"]
        bom_info = boms_by_line_id.get(lid)

        if avail_fixes and unresolved_items:
            coverage_state = "partial_coverage"
        elif avail_fixes and not unresolved_items:
            coverage_state = "full_known_coverage"
        elif excluded_items and not avail_fixes and not unresolved_items:
            coverage_state = "excluded_scope"
        else:
            coverage_state = "no_available_fix"

        line_summaries.append(
            {
                **line,
                "coverage_state": coverage_state,
                "available_fixes": [
                    {
                        "advisory_id": it["advisory_id"],
                        "fixed_by": it["fixed_by"],
                        "consume_coordinate": it["consume_coordinate"],
                    }
                    for it in avail_fixes
                ],
                "remaining_findings": [
                    {
                        "advisory_id": it["advisory_id"],
                        "status": it["status"],
                        "data_quality_state": it["data_quality_state"],
                    }
                    for it in unresolved_items
                    if it["status"] != "excluded"
                ],
                "excluded_findings": [it["advisory_id"] for it in excluded_items],
                "consumption_bom_details": bom_info,
                # Count only primary vulnerability fixes, never inflating by companion BOM/parent/plugin count!
                "unique_vulnerability_fix_count": len({it["advisory_id"] for it in avail_fixes}),
                "companion_artifact_count": len(bom_info["companion_artifacts"]) if bom_info else 0,
            }
        )

    return {
        "schema_version": OSERA_BACKLOG_SNAPSHOT_SCHEMA_VERSION,
        "read_only": True,
        "metadata": {
            "source_repo": source_repo,
            "source_commit": source_commit,
            "source_tag": source_tag,
            "book_version": book_version,
            "view": view,
            "commit_timestamp": commit_timestamp,
            "ingested_at": ingested_at,
            "snapshot_consistent": not any(d["kind"] == "inconsistent_snapshot" for d in data_quality_issues),
        },
        "supported_lines": line_summaries,
        "backlog_items": backlog_items,
        "exclusions": exclusions,
        "consumption_boms": consumption_boms,
        "unexpected_artifacts": unexpected_artifacts,
        "data_quality_issues": data_quality_issues,
    }


def reconcile_backlog_with_estate(
    backlog_snapshot: dict[str, Any],
    estate_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Reconcile an ingested OSERA backlog snapshot against member estate observations (#24).

    Key invariants:
    - Old deployed versions (e.g. `tomcat-embed-core@9.0.50`) remain distinct from `pinned_baseline` (`9.0.70`)
      and `latest_patch` (`9.0.85-osera-00001`); a newer latest-patch reference graph in OSERA NEVER clears
      the member's deployed findings!
    - `open`, `in_progress`, `fixed`, `not_remediable`, and `excluded` backlog states remain distinct from
      member deployment state (`deployed_vulnerable`, `deployed_patched`, `out_of_line_baseline`).
    - Exclusions are treated as scope changes (`excluded_from_osera_scope`), never as member remediation.
    """
    ingested = (
        backlog_snapshot
        if backlog_snapshot.get("schema_version") == OSERA_BACKLOG_SNAPSHOT_SCHEMA_VERSION
        else ingest_osera_backlog_snapshot(backlog_snapshot)
    )

    lines_by_coord: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for line in ingested.get("supported_lines") or []:
        lines_by_coord.setdefault((line["ecosystem_type"], line["library"]), []).append(line)

    items_by_coord: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in ingested.get("backlog_items") or []:
        items_by_coord.setdefault((item["ecosystem_type"], item["library"]), []).append(item)

    reconciled_rows: list[dict[str, Any]] = []
    for obs in estate_observations:
        if not isinstance(obs, dict):
            continue
        app_id = str(obs.get("application_id") or obs.get("project_id") or obs.get("project") or "app").strip()
        raw_purl = str(obs.get("purl") or "").strip()
        if raw_purl:
            parsed = parse_purl(raw_purl)
        else:
            eco = str(obs.get("ecosystem_type") or obs.get("namespace") or "maven").strip().lower()
            lib = str(obs.get("library") or f"{obs.get('meta', '')}:{obs.get('proj', '')}".strip(":")).strip()
            ver = str(obs.get("version") or obs.get("release") or "").strip()
            parsed = parse_purl(f"pkg:{eco}/{lib.replace(':', '/')}@{ver}")

        deployed_version = parsed["version"]
        deployed_minor = _derive_minor_line(deployed_version)
        coord_key = (parsed["ecosystem_type"], parsed["library"])

        candidate_lines = lines_by_coord.get(coord_key, [])
        matched_line = next(
            (ln for ln in candidate_lines if ln.get("maintenance_line") == deployed_minor),
            None,
        )

        coord_items = items_by_coord.get(coord_key, [])
        observed_cves = _split_list_field(obs.get("advisories") or obs.get("cves"))

        def _item_minor_line(item: dict[str, Any]) -> str:
            if item.get("maintenance_line"):
                return str(item["maintenance_line"])
            if item.get("fixed_by_version"):
                return _derive_minor_line(str(item["fixed_by_version"]))
            return ""

        def _is_same_line_item(item: dict[str, Any]) -> bool:
            if matched_line is None:
                return False
            item_lid = str(item.get("line_id") or "")
            if item_lid and matched_line.get("line_id") and item_lid == matched_line["line_id"]:
                item_minor = _item_minor_line(item)
                return not item_minor or item_minor == deployed_minor
            return _item_minor_line(item) == deployed_minor

        line_items = [it for it in coord_items if _is_same_line_item(it)]
        other_line_items = [it for it in coord_items if not _is_same_line_item(it)]

        # Check if the deployed artifact is ALREADY the exact OSERA patched version on its own maintenance line
        exact_patched_items = [
            it
            for it in line_items
            if it["availability_granted"]
            and (it["fixed_by_version"] == deployed_version or it["fixed_by"] == parsed["purl"])
        ]
        is_deployed_patched = len(exact_patched_items) > 0 and "-osera-" in deployed_version

        available_fixes: list[dict[str, Any]] = []
        cross_line_migration_options: list[dict[str, Any]] = []
        future_or_open_work: list[dict[str, Any]] = []
        not_remediable_findings: list[dict[str, Any]] = []
        excluded_findings: list[dict[str, Any]] = []
        active_deployed_findings: list[str] = list(observed_cves)

        for it in line_items:
            if observed_cves and it["advisory_id"] not in observed_cves and not (set(it.get("aliases") or []) & set(observed_cves)):
                continue
            st = it["status"]
            if st == "fixed" and it["availability_granted"]:
                if is_deployed_patched and (it["fixed_by_version"] == deployed_version or it["fixed_by"] == parsed["purl"]):
                    active_deployed_findings = [
                        c for c in active_deployed_findings if c != it["advisory_id"] and c not in set(it.get("aliases") or [])
                    ]
                else:
                    available_fixes.append(
                        {
                            "advisory_id": it["advisory_id"],
                            "backlog_status": "fixed",
                            "maintenance_line": _item_minor_line(it) or deployed_minor,
                            "fixed_by": it["fixed_by"],
                            "consume_coordinate": it["consume_coordinate"],
                        }
                    )
            elif st in ("open", "in_progress") or (st == "fixed" and not it["availability_granted"]):
                future_or_open_work.append(
                    {
                        "advisory_id": it["advisory_id"],
                        "backlog_status": st,
                        "data_quality_state": it["data_quality_state"],
                    }
                )
            elif st == "not_remediable":
                not_remediable_findings.append(
                    {
                        "advisory_id": it["advisory_id"],
                        "backlog_status": "not_remediable",
                    }
                )
            elif st == "excluded":
                # Exclusions are scope changes in OSERA, NEVER remediation of the member's deployed estate!
                excluded_findings.append(
                    {
                        "advisory_id": it["advisory_id"],
                        "backlog_status": "excluded",
                        "remediated_in_estate": False,
                    }
                )

        for it in other_line_items:
            if observed_cves and it["advisory_id"] not in observed_cves and not (set(it.get("aliases") or []) & set(observed_cves)):
                continue
            if it["status"] == "fixed" and it["availability_granted"]:
                cross_line_migration_options.append(
                    {
                        "advisory_id": it["advisory_id"],
                        "maintenance_line": _item_minor_line(it),
                        "line_id": it.get("line_id"),
                        "fixed_by": it["fixed_by"],
                        "consume_coordinate": it["consume_coordinate"],
                    }
                )

        available_fixes.sort(key=lambda x: (str(x.get("advisory_id") or ""), str(x.get("fixed_by") or "")))
        cross_line_migration_options.sort(
            key=lambda x: (str(x.get("maintenance_line") or ""), str(x.get("advisory_id") or ""), str(x.get("fixed_by") or ""))
        )
        future_or_open_work.sort(key=lambda x: (str(x.get("advisory_id") or ""), str(x.get("backlog_status") or "")))
        not_remediable_findings.sort(key=lambda x: str(x.get("advisory_id") or ""))
        excluded_findings.sort(key=lambda x: str(x.get("advisory_id") or ""))

        if matched_line is None:
            coverage_status = "unsupported_maintenance_line"
            member_deployment_state = (
                "deployed_vulnerable_unsupported_line" if active_deployed_findings else "deployed_unsupported_line"
            )
        elif is_deployed_patched and not active_deployed_findings:
            coverage_status = "supported_maintenance_line"
            member_deployment_state = "observed_patched"
        elif is_deployed_patched and active_deployed_findings:
            coverage_status = "supported_maintenance_line"
            member_deployment_state = "partially_patched_with_residual_findings"
        elif available_fixes:
            coverage_status = "supported_maintenance_line"
            member_deployment_state = "deployed_vulnerable_fix_available"
        else:
            coverage_status = "supported_maintenance_line"
            member_deployment_state = "deployed_vulnerable_no_available_fix"

        reconciled_rows.append(
            {
                "application_id": app_id,
                "deployed_purl": parsed["purl"],
                "library": parsed["library"],
                "deployed_version": deployed_version,
                "deployed_maintenance_line": deployed_minor,
                "matched_line_id": matched_line["line_id"] if matched_line else None,
                "coverage_status": coverage_status,
                "pinned_baseline": matched_line["pinned_baseline"] if matched_line else None,
                "latest_patch_resolution": matched_line["latest_patch"] if matched_line else None,
                "consume_coordinate": matched_line["consume_coordinate"] if matched_line else None,
                "consumption_bom": matched_line["consumption_bom_details"] if matched_line else None,
                "member_deployment_state": member_deployment_state,
                "deployed_findings_cleared_by_reference_graph": False,
                "active_deployed_findings": active_deployed_findings,
                "available_fixes": available_fixes,
                "cross_line_migration_options": cross_line_migration_options,
                "future_or_open_work": future_or_open_work,
                "not_remediable_findings": not_remediable_findings,
                "excluded_findings": excluded_findings,
            }
        )

    return {
        "schema_version": OSERA_BACKLOG_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_metadata": ingested["metadata"],
        "rows": reconciled_rows,
        "data_quality_issues": ingested["data_quality_issues"],
    }

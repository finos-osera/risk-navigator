#!/usr/bin/env python3
"""Load patch feeds (OSERA OpenVEX & provider-neutral catalogs) and measure estate patch availability and adoption (#41)."""

from __future__ import annotations

import argparse
import copy
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

VALID_VEX_STATUSES = ("fixed", "affected", "not_affected", "under_investigation")
RELEASED_STATES = ("released",)
UNRELEASED_STATES = ("planned", "supported_line", "backlog_closed", "draft", "candidate")
INACTIVE_STATES = ("withdrawn", "superseded")

ECOSYSTEM_LABELS = {
    "maven": "Java",
    "npm": "JavaScript",
    "pypi": "Python",
    "nuget": ".NET",
    "cargo": "Rust",
    "golang": "Go",
    "gem": "Ruby",
    "composer": "PHP",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "docker": "Docker",
    "oci": "OCI",
}

OSERA_VERSION_RE = re.compile(r"^(?P<base>.+)-osera-(?P<seq>\d+)$")
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


def _parse_iso_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def parse_purl(purl: Any) -> dict[str, Any]:
    """Parse a Package URL (PURL) in alignment with OSERA community#39 / community#40 feed-data.mjs."""
    if not isinstance(purl, str) or not purl.strip():
        return {
            "valid": False,
            "purl": str(purl or ""),
            "ecosystem_type": "unknown",
            "ecosystem": "Unknown",
            "library": "",
            "version": "",
            "error": "Missing product identifier",
        }
    raw = purl.strip()
    match = re.match(r"^pkg:([^/]+)/(.+)$", raw)
    if not match:
        return {
            "valid": False,
            "purl": raw,
            "ecosystem_type": "other",
            "ecosystem": "Other",
            "library": raw,
            "version": "",
            "error": f"Unsupported or non-PURL product identifier: {raw}",
        }
    eco_type = match.group(1).strip().lower()
    coordinate = match.group(2).split("?")[0].split("#")[0]
    at_idx = coordinate.rfind("@")
    if at_idx < 0:
        decoded_lib = unquote(coordinate).replace("/", ":")
        return {
            "valid": False,
            "purl": raw,
            "ecosystem_type": eco_type,
            "ecosystem": ECOSYSTEM_LABELS.get(eco_type, eco_type),
            "library": decoded_lib,
            "version": "",
            "error": f"Missing version in product PURL: {raw}",
        }
    decoded_lib = unquote(coordinate[:at_idx]).replace("/", ":")
    decoded_ver = unquote(coordinate[at_idx + 1 :]).strip()
    if not decoded_lib or not decoded_ver:
        return {
            "valid": False,
            "purl": raw,
            "ecosystem_type": eco_type,
            "ecosystem": ECOSYSTEM_LABELS.get(eco_type, eco_type),
            "library": decoded_lib,
            "version": decoded_ver,
            "error": f"Incomplete package coordinate or version in PURL: {raw}",
        }
    return {
        "valid": True,
        "purl": f"pkg:{eco_type}/{coordinate[:at_idx]}@{decoded_ver}",
        "ecosystem_type": eco_type,
        "ecosystem": ECOSYSTEM_LABELS.get(eco_type, eco_type),
        "library": decoded_lib,
        "version": decoded_ver,
        "error": None,
    }


def extract_osera_maintenance_line(version: str) -> dict[str, Any] | None:
    """Extract base version and numeric sequence from an `<upstream>-osera-<N>` version tag."""
    if not isinstance(version, str):
        return None
    match = OSERA_VERSION_RE.match(version.strip())
    if not match:
        return None
    base = match.group("base")
    seq = int(match.group("seq"))
    return {
        "base_version": base,
        "maintenance_line": _derive_minor_line(base),
        "sequence": seq,
    }


def _derive_minor_line(version: str) -> str:
    raw = str(version or "").strip()
    if not raw:
        return ""
    osera = OSERA_VERSION_RE.match(raw)
    if osera:
        raw = osera.group("base")
    num_match = re.match(r"^(\d+\.\d+)", raw)
    if num_match:
        return f"{num_match.group(1)}.x"
    return raw


def normalize_openvex_feed(feed_config: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    """Normalize an OSERA OpenVEX feed (community#39 / community#40 contract) plus optional catalog overlays."""
    feed_id = str(feed_config.get("feed_id") or "osera-openvex").strip()
    source_url = str(feed_config.get("source_url") or "https://feed.finos.org/openvex.json").strip()
    enabled = bool(feed_config.get("enabled", True))
    last_refresh = (
        _parse_iso_timestamp(feed_config.get("last_refresh"))
        or _parse_iso_timestamp(document.get("last_updated"))
        or _parse_iso_timestamp(document.get("updated"))
        or _parse_iso_timestamp(document.get("timestamp"))
    )
    snapshot_version = str(document.get("version") or feed_config.get("snapshot_version") or "unknown")
    validation_errors: list[str] = []
    validation_warnings: list[str] = []
    ambiguous_records: list[dict[str, Any]] = []

    if not last_refresh:
        validation_errors.append("Missing valid publication timestamp (last_updated / updated / timestamp).")

    statements = document.get("statements")
    if not isinstance(statements, list):
        validation_errors.append("Invalid OpenVEX document: 'statements' must be a list.")
        statements = []

    overlay_by_purl: dict[str, dict[str, Any]] = {}
    for item in feed_config.get("catalog_overlays") or []:
        if isinstance(item, dict) and item.get("replacement_purl"):
            overlay_by_purl[str(item["replacement_purl"]).strip()] = item

    vex_statements: list[dict[str, Any]] = []
    patch_records_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    seen_statement_keys: set[str] = set()

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            validation_errors.append(f"Statement[{idx}] is not an object.")
            continue
        vuln_obj = stmt.get("vulnerability")
        if not isinstance(vuln_obj, dict):
            validation_errors.append(f"Statement[{idx}] is missing vulnerability object.")
            continue
        vuln_id = str(vuln_obj.get("name") or vuln_obj.get("@id") or "").strip()
        status = str(stmt.get("status") or "").strip()
        products = stmt.get("products")
        if not vuln_id or status not in VALID_VEX_STATUSES or not isinstance(products, list) or not products:
            validation_errors.append(
                f"Statement[{idx}] has invalid vulnerability ({vuln_id!r}), status ({status!r}), or empty products."
            )
            continue

        aliases = [
            str(a).strip()
            for a in (vuln_obj.get("aliases") or [])
            if isinstance(a, str) and str(a).strip()
        ]
        supplier = str(stmt.get("supplier") or feed_config.get("provider") or "OSERA").strip()
        stmt_timestamp = _parse_iso_timestamp(stmt.get("timestamp")) or last_refresh or ""

        for prod in products:
            raw_purl = prod.get("@id") if isinstance(prod, dict) else prod
            parsed = parse_purl(raw_purl)
            dedup_sig = json.dumps(
                [raw_purl, vuln_id, status, supplier, stmt_timestamp, sorted(aliases)],
                sort_keys=True,
            )
            if dedup_sig in seen_statement_keys:
                continue
            seen_statement_keys.add(dedup_sig)

            if not parsed["valid"]:
                ambiguous_records.append(
                    {
                        "feed_id": feed_id,
                        "statement_index": idx,
                        "product_id": str(raw_purl or ""),
                        "vulnerability": vuln_id,
                        "status": status,
                        "reason": parsed["error"],
                    }
                )
                validation_warnings.append(f"Ambiguous product in statement[{idx}]: {parsed['error']}")
                continue

            purl = parsed["purl"]
            osera_line = extract_osera_maintenance_line(parsed["version"])
            vex_entry = {
                "feed_id": feed_id,
                "provider": str(feed_config.get("provider") or "OSERA"),
                "provider_kind": str(feed_config.get("provider_kind") or ("osera" if osera_line else "upstream")),
                "supplier": supplier,
                "purl": purl,
                "ecosystem_type": parsed["ecosystem_type"],
                "ecosystem": parsed["ecosystem"],
                "library": parsed["library"],
                "version": parsed["version"],
                "base_version": osera_line["base_version"] if osera_line else parsed["version"],
                "maintenance_line": (
                    osera_line["maintenance_line"] if osera_line else _derive_minor_line(parsed["version"])
                ),
                "osera_sequence": osera_line["sequence"] if osera_line else None,
                "vulnerability": vuln_id,
                "aliases": aliases,
                "status": status,
                "timestamp": stmt_timestamp,
            }
            vex_statements.append(vex_entry)

            # Only 'fixed' VEX statements represent candidate patch releases;
            # 'not_affected', 'affected', and 'under_investigation' are preserved in vex_statements
            # and never synthesized into patch releases.
            if status == "fixed":
                key = (purl, supplier)
                overlay = overlay_by_purl.get(purl, {})
                if key not in patch_records_by_key:
                    applicable_versions = list(overlay.get("applicable_versions") or [])
                    if osera_line and osera_line["base_version"] not in applicable_versions:
                        applicable_versions.append(osera_line["base_version"])
                    release_state = str(overlay.get("release_state") or "released").strip().lower()
                    withdrawn = bool(overlay.get("withdrawn", False)) or release_state == "withdrawn"
                    patch_records_by_key[key] = {
                        "feed_id": feed_id,
                        "source_url": source_url,
                        "snapshot_version": snapshot_version,
                        "provider": str(feed_config.get("provider") or "OSERA"),
                        "provider_kind": str(
                            overlay.get("provider_kind")
                            or feed_config.get("provider_kind")
                            or ("osera" if osera_line else "upstream")
                        ),
                        "supplier": supplier,
                        "patch_id": str(overlay.get("patch_id") or f"{feed_id}:{purl}"),
                        "ecosystem_type": parsed["ecosystem_type"],
                        "ecosystem": parsed["ecosystem"],
                        "library": parsed["library"],
                        "applicable_versions": applicable_versions,
                        "maintenance_line": str(
                            overlay.get("maintenance_line")
                            or (osera_line["maintenance_line"] if osera_line else _derive_minor_line(parsed["version"]))
                        ),
                        "replacement_version": parsed["version"],
                        "replacement_purl": purl,
                        "osera_sequence": osera_line["sequence"] if osera_line else None,
                        "artifact_digest": overlay.get("artifact_digest"),
                        "fixed_advisories": [],
                        "aliases": [],
                        "residual_advisories": list(overlay.get("residual_advisories") or []),
                        "release_state": "withdrawn" if withdrawn else release_state,
                        "withdrawn": withdrawn,
                        "superseded_by": overlay.get("superseded_by"),
                        "required_companions": list(overlay.get("required_companions") or []),
                        "evidence_links": list(
                            overlay.get("evidence_links")
                            or [
                                {"kind": "openvex", "url": source_url},
                            ]
                        ),
                        "published_at": stmt_timestamp,
                    }
                rec = patch_records_by_key[key]
                if vuln_id not in rec["fixed_advisories"]:
                    rec["fixed_advisories"].append(vuln_id)
                for alias in aliases:
                    if alias not in rec["aliases"]:
                        rec["aliases"].append(alias)

    # Mark older numeric -osera-N tags on the same (ecosystem, library, supplier, base_version) line as superseded
    highest_seq_by_line: dict[tuple[str, str, str, str], tuple[int, str]] = {}
    for rec in patch_records_by_key.values():
        osera_line = extract_osera_maintenance_line(rec["replacement_version"])
        if not osera_line:
            continue
        line_key = (rec["ecosystem_type"], rec["library"], rec["supplier"], osera_line["base_version"])
        seq = osera_line["sequence"]
        if line_key not in highest_seq_by_line or seq > highest_seq_by_line[line_key][0]:
            highest_seq_by_line[line_key] = (seq, rec["replacement_purl"])

    for rec in patch_records_by_key.values():
        osera_line = extract_osera_maintenance_line(rec["replacement_version"])
        if not osera_line:
            continue
        line_key = (rec["ecosystem_type"], rec["library"], rec["supplier"], osera_line["base_version"])
        max_seq, latest_purl = highest_seq_by_line[line_key]
        if osera_line["sequence"] < max_seq and not rec.get("superseded_by"):
            rec["superseded_by"] = latest_purl

    return {
        "feed_id": feed_id,
        "adapter": "osera_openvex",
        "provider": str(feed_config.get("provider") or "OSERA"),
        "provider_kind": str(feed_config.get("provider_kind") or "osera"),
        "source_url": source_url,
        "snapshot_version": snapshot_version,
        "last_refresh": last_refresh,
        "enabled": enabled,
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings,
        "ambiguous_records": ambiguous_records,
        "vex_statements": vex_statements,
        "patches": list(patch_records_by_key.values()),
    }


def normalize_catalog_feed(feed_config: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    """Normalize a provider-neutral or member-supplied patch catalog feed (#23 / #41)."""
    feed_id = str(feed_config.get("feed_id") or document.get("feed_id") or "member-catalog").strip()
    source_url = str(feed_config.get("source_url") or document.get("source_url") or "local://catalog").strip()
    enabled = bool(feed_config.get("enabled", document.get("enabled", True)))
    last_refresh = (
        _parse_iso_timestamp(feed_config.get("last_refresh"))
        or _parse_iso_timestamp(document.get("as_of"))
        or _parse_iso_timestamp(document.get("updated"))
        or _parse_iso_timestamp(document.get("timestamp"))
    )
    snapshot_version = str(document.get("snapshot_version") or document.get("version") or "1.0")
    validation_errors: list[str] = []
    validation_warnings: list[str] = []
    ambiguous_records: list[dict[str, Any]] = []

    if not last_refresh:
        validation_errors.append("Missing valid catalog snapshot timestamp (as_of / updated / timestamp).")

    raw_patches = document.get("patches")
    if not isinstance(raw_patches, list):
        validation_errors.append("Invalid catalog feed: 'patches' must be a list.")
        raw_patches = []

    patches: list[dict[str, Any]] = []
    vex_statements: list[dict[str, Any]] = []
    seen_patch_keys: set[str] = set()

    for idx, item in enumerate(raw_patches):
        if not isinstance(item, dict):
            validation_errors.append(f"Patch[{idx}] is not an object.")
            continue
        patch_id = str(item.get("patch_id") or f"{feed_id}-patch-{idx}").strip()
        replacement_purl = str(item.get("replacement_purl") or "").strip()
        parsed = parse_purl(replacement_purl)
        if not parsed["valid"]:
            ambiguous_records.append(
                {
                    "feed_id": feed_id,
                    "patch_id": patch_id,
                    "product_id": replacement_purl,
                    "reason": parsed["error"],
                }
            )
            validation_warnings.append(f"Invalid replacement_purl in patch {patch_id}: {parsed['error']}")
            continue

        dedup_key = json.dumps(
            [
                patch_id,
                parsed["purl"],
                sorted(str(x) for x in (item.get("fixed_advisories") or [])),
                str(item.get("release_state") or "released"),
                str(item.get("artifact_digest") or ""),
            ]
        )
        if dedup_key in seen_patch_keys:
            continue
        seen_patch_keys.add(dedup_key)

        osera_line = extract_osera_maintenance_line(parsed["version"])
        release_state = str(item.get("release_state") or "released").strip().lower()
        withdrawn = bool(item.get("withdrawn", False)) or release_state == "withdrawn"
        if withdrawn:
            release_state = "withdrawn"

        applicable_versions = [
            str(v).strip() for v in (item.get("applicable_versions") or []) if str(v).strip()
        ]
        if osera_line and osera_line["base_version"] not in applicable_versions:
            applicable_versions.append(osera_line["base_version"])

        provider = str(item.get("provider") or feed_config.get("provider") or "Member").strip()
        provider_kind = str(
            item.get("provider_kind")
            or feed_config.get("provider_kind")
            or ("osera" if osera_line else "member")
        ).strip().lower()

        patches.append(
            {
                "feed_id": feed_id,
                "source_url": source_url,
                "snapshot_version": snapshot_version,
                "provider": provider,
                "provider_kind": provider_kind,
                "supplier": str(item.get("supplier") or provider),
                "patch_id": patch_id,
                "ecosystem_type": parsed["ecosystem_type"],
                "ecosystem": parsed["ecosystem"],
                "library": parsed["library"],
                "applicable_versions": applicable_versions,
                "maintenance_line": str(
                    item.get("maintenance_line")
                    or (osera_line["maintenance_line"] if osera_line else _derive_minor_line(parsed["version"]))
                ),
                "replacement_version": parsed["version"],
                "replacement_purl": parsed["purl"],
                "osera_sequence": osera_line["sequence"] if osera_line else None,
                "artifact_digest": item.get("artifact_digest"),
                "fixed_advisories": [
                    str(a).strip() for a in (item.get("fixed_advisories") or []) if str(a).strip()
                ],
                "aliases": [str(a).strip() for a in (item.get("aliases") or []) if str(a).strip()],
                "residual_advisories": [
                    str(a).strip() for a in (item.get("residual_advisories") or []) if str(a).strip()
                ],
                "release_state": release_state,
                "withdrawn": withdrawn,
                "superseded_by": item.get("superseded_by"),
                "required_companions": list(item.get("required_companions") or []),
                "evidence_links": list(item.get("evidence_links") or [{"kind": "catalog", "url": source_url}]),
                "published_at": _parse_iso_timestamp(item.get("published_at")) or last_refresh or "",
            }
        )

    for idx, stmt in enumerate(document.get("vex_statements") or []):
        if not isinstance(stmt, dict):
            continue
        parsed = parse_purl(stmt.get("purl") or stmt.get("product_id"))
        status = str(stmt.get("status") or "").strip()
        vuln_id = str(stmt.get("vulnerability") or "").strip()
        if not parsed["valid"] or status not in VALID_VEX_STATUSES or not vuln_id:
            validation_warnings.append(f"Skipped invalid catalog VEX statement[{idx}].")
            continue
        vex_statements.append(
            {
                "feed_id": feed_id,
                "provider": str(feed_config.get("provider") or "Member"),
                "provider_kind": str(feed_config.get("provider_kind") or "member"),
                "supplier": str(stmt.get("supplier") or feed_config.get("provider") or "Member"),
                "purl": parsed["purl"],
                "ecosystem_type": parsed["ecosystem_type"],
                "ecosystem": parsed["ecosystem"],
                "library": parsed["library"],
                "version": parsed["version"],
                "base_version": parsed["version"],
                "maintenance_line": _derive_minor_line(parsed["version"]),
                "osera_sequence": None,
                "vulnerability": vuln_id,
                "aliases": [str(a).strip() for a in (stmt.get("aliases") or []) if str(a).strip()],
                "status": status,
                "timestamp": _parse_iso_timestamp(stmt.get("timestamp")) or last_refresh or "",
            }
        )

    return {
        "feed_id": feed_id,
        "adapter": "provider_catalog",
        "provider": str(feed_config.get("provider") or document.get("provider") or "Member"),
        "provider_kind": str(feed_config.get("provider_kind") or document.get("provider_kind") or "member"),
        "source_url": source_url,
        "snapshot_version": snapshot_version,
        "last_refresh": last_refresh,
        "enabled": enabled,
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings,
        "ambiguous_records": ambiguous_records,
        "vex_statements": vex_statements,
        "patches": patches,
    }


def load_patch_feeds(feeds_bundle: list[dict[str, Any]]) -> dict[str, Any]:
    """Load and merge multiple patch feeds idempotently while preserving provenance and conflicts."""
    feed_summaries: list[dict[str, Any]] = []
    merged_by_purl: dict[str, dict[str, Any]] = {}
    all_vex_statements: list[dict[str, Any]] = []
    all_ambiguous_records: list[dict[str, Any]] = []
    feed_conflicts: list[dict[str, Any]] = []

    seen_feed_snapshots: set[str] = set()
    seen_vex_keys: set[str] = set()

    for raw_feed in feeds_bundle or []:
        if not isinstance(raw_feed, dict):
            continue
        feed_cfg = raw_feed.get("config") if isinstance(raw_feed.get("config"), dict) else raw_feed
        doc = raw_feed.get("document") if isinstance(raw_feed.get("document"), dict) else raw_feed
        adapter = str(feed_cfg.get("adapter") or doc.get("adapter") or "provider_catalog").strip().lower()

        if adapter == "osera_openvex" or "statements" in doc:
            normalized = normalize_openvex_feed(feed_cfg, doc)
        else:
            normalized = normalize_catalog_feed(feed_cfg, doc)

        # Idempotent repeated feed import guard: identical (feed_id, snapshot_version, patches, vex) is deduplicated
        snapshot_sig = json.dumps(
            {
                "feed_id": normalized["feed_id"],
                "snapshot_version": normalized["snapshot_version"],
                "enabled": normalized["enabled"],
                "patches": normalized["patches"],
                "vex_statements": normalized["vex_statements"],
            },
            sort_keys=True,
        )
        if snapshot_sig in seen_feed_snapshots:
            continue
        seen_feed_snapshots.add(snapshot_sig)

        feed_summaries.append(
            {
                "feed_id": normalized["feed_id"],
                "adapter": normalized["adapter"],
                "provider": normalized["provider"],
                "provider_kind": normalized["provider_kind"],
                "source_url": normalized["source_url"],
                "snapshot_version": normalized["snapshot_version"],
                "last_refresh": normalized["last_refresh"],
                "enabled": normalized["enabled"],
                "patch_count": len(normalized["patches"]),
                "vex_statement_count": len(normalized["vex_statements"]),
                "validation_errors": normalized["validation_errors"],
                "validation_warnings": normalized["validation_warnings"],
                "ambiguous_record_count": len(normalized["ambiguous_records"]),
            }
        )
        all_ambiguous_records.extend(normalized["ambiguous_records"])

        if not normalized["enabled"] or normalized["validation_errors"]:
            continue

        for vex in normalized["vex_statements"]:
            vex_key = json.dumps(
                [
                    vex["feed_id"],
                    vex["purl"],
                    vex["vulnerability"],
                    vex["status"],
                    vex["supplier"],
                ],
                sort_keys=True,
            )
            if vex_key not in seen_vex_keys:
                seen_vex_keys.add(vex_key)
                all_vex_statements.append(vex)

        for patch in normalized["patches"]:
            purl = patch["replacement_purl"]
            merged_by_purl.setdefault(purl, []).append(copy.deepcopy(patch))

    reconciled_patches: dict[str, dict[str, Any]] = {}
    for purl, raw_records in merged_by_purl.items():
        ordered_records = sorted(
            raw_records,
            key=lambda r: (
                0 if str(r.get("provider_kind") or "") == "osera" else 1,
                str(r.get("feed_id") or ""),
                str(r.get("patch_id") or ""),
            ),
        )
        merged = copy.deepcopy(ordered_records[0])
        merged["provenance"] = []
        merged["conflicting_evidence"] = []
        merged["fixed_advisories"] = []
        merged["aliases"] = []
        merged["applicable_versions"] = []
        merged["residual_advisories"] = []
        merged["evidence_links"] = []
        merged["required_companions"] = []

        distinct_digests: dict[str, list[str]] = {}
        distinct_states: dict[str, list[str]] = {}

        for rec in ordered_records:
            provenance_entry = {
                "feed_id": rec["feed_id"],
                "provider": rec["provider"],
                "provider_kind": rec["provider_kind"],
                "supplier": rec["supplier"],
                "patch_id": rec["patch_id"],
                "snapshot_version": rec["snapshot_version"],
                "source_url": rec["source_url"],
                "release_state": rec["release_state"],
                "artifact_digest": rec.get("artifact_digest"),
                "published_at": rec.get("published_at"),
            }
            if provenance_entry not in merged["provenance"]:
                merged["provenance"].append(provenance_entry)

            for adv in rec.get("fixed_advisories") or []:
                if adv not in merged["fixed_advisories"]:
                    merged["fixed_advisories"].append(adv)
            for alias in rec.get("aliases") or []:
                if alias not in merged["aliases"]:
                    merged["aliases"].append(alias)
            for ver in rec.get("applicable_versions") or []:
                if ver not in merged["applicable_versions"]:
                    merged["applicable_versions"].append(ver)
            for res_adv in rec.get("residual_advisories") or []:
                if res_adv not in merged["residual_advisories"]:
                    merged["residual_advisories"].append(res_adv)
            for link in rec.get("evidence_links") or []:
                if link not in merged["evidence_links"]:
                    merged["evidence_links"].append(link)
            for comp in rec.get("required_companions") or []:
                if comp not in merged["required_companions"]:
                    merged["required_companions"].append(comp)

            digest_val = str(rec.get("artifact_digest") or "").strip()
            if digest_val:
                distinct_digests.setdefault(digest_val, [])
                if rec["feed_id"] not in distinct_digests[digest_val]:
                    distinct_digests[digest_val].append(rec["feed_id"])

            state_val = str(rec.get("release_state") or "released").strip().lower()
            distinct_states.setdefault(state_val, [])
            if rec["feed_id"] not in distinct_states[state_val]:
                distinct_states[state_val].append(rec["feed_id"])

        # Order-independent artifact_digest reconciliation across feeds:
        # - If one feed omits artifact_digest and another supplies it, preserve the non-null digest.
        # - If active feeds supply conflicting non-null digests, record a deterministic conflict.
        if len(distinct_digests) == 1:
            merged["artifact_digest"] = next(iter(distinct_digests.keys()))
        elif len(distinct_digests) > 1:
            merged["artifact_digest"] = None
            conflict_feeds = sorted({fid for fids in distinct_digests.values() for fid in fids})
            conflict = {
                "replacement_purl": purl,
                "reason": "Cross-feed artifact_digest disagreement",
                "feeds": conflict_feeds,
                "digests": sorted(distinct_digests.keys()),
            }
            merged["conflicting_evidence"].append(conflict)
            feed_conflicts.append(conflict)
        else:
            merged["artifact_digest"] = None

        if len(distinct_states) > 1:
            conflict_feeds = sorted({fid for fids in distinct_states.values() for fid in fids})
            conflict = {
                "replacement_purl": purl,
                "reason": "Cross-feed release_state disagreement",
                "feeds": conflict_feeds,
                "states": sorted(distinct_states.keys()),
            }
            merged["conflicting_evidence"].append(conflict)
            feed_conflicts.append(conflict)
            if any(r.get("withdrawn") or r.get("release_state") == "withdrawn" for r in ordered_records):
                merged["withdrawn"] = True
                merged["release_state"] = "withdrawn"

        reconciled_patches[purl] = merged

    # Also detect VEX status disagreements across feeds for the same (purl, vulnerability)
    vex_by_pair: dict[tuple[str, str], set[str]] = {}
    for vex in all_vex_statements:
        pair = (vex["purl"], vex["vulnerability"].upper())
        vex_by_pair.setdefault(pair, set()).add(vex["status"])
    for (purl, vuln), statuses in vex_by_pair.items():
        if len(statuses) > 1:
            conflict = {
                "purl": purl,
                "vulnerability": vuln,
                "reason": "Conflicting VEX statuses for identical product and vulnerability",
                "statuses": sorted(statuses),
            }
            feed_conflicts.append(conflict)
            if purl in reconciled_patches:
                reconciled_patches[purl]["conflicting_evidence"].append(conflict)

    return {
        "feeds": feed_summaries,
        "patches": list(reconciled_patches.values()),
        "vex_statements": all_vex_statements,
        "ambiguous_records": all_ambiguous_records,
        "feed_conflicts": feed_conflicts,
    }


def _is_usable_released_patch(patch: dict[str, Any]) -> tuple[bool, str | None]:
    if patch.get("withdrawn") or patch.get("release_state") == "withdrawn":
        return False, "withdrawn_artifact"
    if patch.get("release_state") in UNRELEASED_STATES:
        return False, f"unreleased_work:{patch.get('release_state')}"
    if patch.get("release_state") not in RELEASED_STATES:
        return False, f"non_released_state:{patch.get('release_state')}"
    if patch.get("conflicting_evidence"):
        return False, "conflicting_feed_evidence"
    return True, None


def _parse_numeric_version_prefix(version: str) -> tuple[int, ...] | None:
    raw = str(version or "").strip()
    if not raw:
        return None
    osera = OSERA_VERSION_RE.match(raw)
    if osera:
        raw = osera.group("base")
    nums = re.findall(r"\d+", raw.split("-")[0])
    if not nums:
        return None
    return tuple(int(n) for n in nums)


def _matches_applicable_scope(
    patch: dict[str, Any],
    ecosystem_type: str,
    library: str,
    observed_version: str,
    observed_cves: list[str],
) -> bool:
    if patch["ecosystem_type"] != ecosystem_type or patch["library"] != library:
        return False
    if observed_version == patch["replacement_version"]:
        return True
    applicable_versions = patch.get("applicable_versions") or []
    if observed_version in applicable_versions:
        return True
    obs_osera = extract_osera_maintenance_line(observed_version)
    if obs_osera and obs_osera["base_version"] in applicable_versions:
        return True
    obs_line = _derive_minor_line(observed_version)
    if obs_line and obs_line == patch.get("maintenance_line"):
        # Never offer a maintenance-line fallback to an observation that has no CVEs
        if not observed_cves:
            return False
        patch_advs = {a.upper() for a in (patch.get("fixed_advisories") or []) + (patch.get("aliases") or [])}
        if not any(c.upper() in patch_advs for c in observed_cves):
            return False
        obs_ver_tuple = _parse_numeric_version_prefix(observed_version)
        patch_base_tuple = _parse_numeric_version_prefix(patch["replacement_version"])
        if obs_ver_tuple is not None and patch_base_tuple is not None and obs_ver_tuple > patch_base_tuple:
            return False
        return True
    return False


def evaluate_estate_patch_adoption(
    estate_snapshot: dict[str, Any],
    feeds_bundle: list[dict[str, Any]],
) -> dict[str, Any]:
    """Join normalized patch feeds and VEX statements against an estate SBOM/build snapshot."""
    catalog = load_patch_feeds(feeds_bundle)
    patches = catalog["patches"]
    vex_statements = catalog["vex_statements"]

    snapshot_id = str(estate_snapshot.get("snapshot_id") or "estate-default")
    snapshot_date = (
        _parse_iso_timestamp(estate_snapshot.get("snapshot_date"))
        or _parse_iso_timestamp(estate_snapshot.get("as_of"))
        or "unknown"
    )
    stale_after_days = int(estate_snapshot.get("stale_after_days") or 30)

    raw_apps = estate_snapshot.get("applications") or []
    all_app_ids: set[str] = set()
    app_meta_by_id: dict[str, dict[str, Any]] = {}

    # Reconcile component observations per (app_id, purl_or_raw_id) order-independently
    # while tracking direct/transitive scopes and all observed artifact digests so
    # conflicting or missing digests on a duplicate row are never masked by row ordering.
    obs_by_app_and_coord: dict[tuple[str, str], dict[str, Any]] = {}

    for app in raw_apps:
        if not isinstance(app, dict):
            continue
        app_id = str(app.get("application_id") or app.get("id") or "").strip()
        if not app_id:
            continue
        all_app_ids.add(app_id)
        app_meta_by_id[app_id] = {
            "application_id": app_id,
            "name": str(app.get("name") or app_id),
            "project_group": str(app.get("project_group") or "General"),
            "observed_at": _parse_iso_timestamp(app.get("observed_at")) or snapshot_date,
        }
        for comp in app.get("components") or []:
            if not isinstance(comp, dict):
                continue
            raw_purl = str(comp.get("purl") or comp.get("id") or "").strip()
            parsed = parse_purl(raw_purl)
            coord_key = parsed["purl"] if parsed["valid"] else raw_purl
            key = (app_id, coord_key)
            dep_scope = str(comp.get("dependency_scope") or ("direct" if comp.get("direct") else "transitive")).lower()
            cves = [str(c).strip() for c in (comp.get("cves") or []) if str(c).strip()]
            kev_cves = [str(c).strip() for c in (comp.get("kev_cves") or []) if str(c).strip()]
            raw_digest = str(comp.get("artifact_digest") or "").strip() or None
            if key not in obs_by_app_and_coord:
                obs_by_app_and_coord[key] = {
                    "instance_id": f"{app_id}::{coord_key}",
                    "application_id": app_id,
                    "project_group": app_meta_by_id[app_id]["project_group"],
                    "raw_purl": raw_purl,
                    "parsed": parsed,
                    "artifact_digest": raw_digest,
                    "observed_digests": {raw_digest} if raw_digest else set(),
                    "missing_digest_rows": 0 if raw_digest else 1,
                    "observation_rows": 1,
                    "dependency_scopes": {dep_scope},
                    "cves": list(dict.fromkeys(cves)),
                    "kev_cves": list(dict.fromkeys(kev_cves)),
                    "observed_at": _parse_iso_timestamp(comp.get("observed_at"))
                    or app_meta_by_id[app_id]["observed_at"],
                }
            else:
                existing = obs_by_app_and_coord[key]
                existing["observation_rows"] += 1
                existing["dependency_scopes"].add(dep_scope)
                for c in cves:
                    if c not in existing["cves"]:
                        existing["cves"].append(c)
                for k in kev_cves:
                    if k not in existing["kev_cves"]:
                        existing["kev_cves"].append(k)
                if raw_digest:
                    existing["observed_digests"].add(raw_digest)
                else:
                    existing["missing_digest_rows"] += 1
                # Deterministic canonical digest: only populated if unambiguous across all observed rows
                if len(existing["observed_digests"]) == 1 and existing["missing_digest_rows"] == 0:
                    existing["artifact_digest"] = next(iter(existing["observed_digests"]))
                else:
                    existing["artifact_digest"] = None

    instance_records: list[dict[str, Any]] = []
    package_line_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}

    for obs in obs_by_app_and_coord.values():
        parsed = obs["parsed"]
        stale_obs = False
        if snapshot_date != "unknown" and obs.get("observed_at") and obs["observed_at"] != "unknown":
            try:
                snap_dt = datetime.fromisoformat(snapshot_date.replace("Z", "+00:00"))
                obs_dt = datetime.fromisoformat(obs["observed_at"].replace("Z", "+00:00"))
                if (snap_dt - obs_dt).days > stale_after_days:
                    stale_obs = True
            except ValueError:
                pass

        if not parsed["valid"]:
            rec = {
                "instance_id": obs["instance_id"],
                "application_id": obs["application_id"],
                "project_group": obs["project_group"],
                "raw_purl": obs["raw_purl"],
                "purl": obs["raw_purl"],
                "ecosystem_type": "unknown",
                "ecosystem": "Unknown",
                "library": obs["raw_purl"] or "unknown",
                "version": "",
                "maintenance_line": "unknown",
                "dependency_scopes": sorted(obs["dependency_scopes"]),
                "cves": obs["cves"],
                "kev_cves": obs["kev_cves"],
                "eligible": False,
                "instance_state": "unknown_evidence",
                "package_adoption_state": "unknown_evidence",
                "reason": parsed["error"],
                "applicable_patches": [],
                "blocked_candidates": [],
                "vex_assessments": [],
                "matched_patch": None,
                "addressed_cves": [],
                "addressed_kev_cves": [],
                "potential_cves": [],
                "potential_kev_cves": [],
                "residual_cves": list(obs["cves"]),
                "observation_basis": "sbom_build_observation_not_verified_runtime",
                "stale_observation": stale_obs,
            }
            instance_records.append(rec)
            continue

        eco_type = parsed["ecosystem_type"]
        lib_name = parsed["library"]
        ver = parsed["version"]
        osera_line = extract_osera_maintenance_line(ver)
        maint_line = osera_line["maintenance_line"] if osera_line else _derive_minor_line(ver)

        # Match VEX statements for this package/version or base version
        matching_vex = [
            v
            for v in vex_statements
            if v["ecosystem_type"] == eco_type
            and v["library"] == lib_name
            and (
                v["version"] == ver
                or v["base_version"] == ver
                or (osera_line and v["base_version"] == osera_line["base_version"])
            )
        ]

        # Match candidate patches for this package & maintenance line
        usable_patches: list[dict[str, Any]] = []
        blocked_candidates: list[dict[str, Any]] = []
        for patch in patches:
            if not _matches_applicable_scope(patch, eco_type, lib_name, ver, obs["cves"]):
                continue
            usable, blocked_reason = _is_usable_released_patch(patch)
            if usable:
                # Prefer non-superseded patches unless the observed version is itself the superseded tag
                if patch.get("superseded_by") and ver != patch["replacement_version"]:
                    blocked_candidates.append(
                        {
                            "patch_id": patch["patch_id"],
                            "replacement_purl": patch["replacement_purl"],
                            "provider": patch["provider"],
                            "provider_kind": patch["provider_kind"],
                            "blocked_reason": f"superseded_by:{patch['superseded_by']}",
                        }
                    )
                    continue
                usable_patches.append(patch)
            else:
                blocked_candidates.append(
                    {
                        "patch_id": patch["patch_id"],
                        "replacement_purl": patch["replacement_purl"],
                        "provider": patch["provider"],
                        "provider_kind": patch["provider_kind"],
                        "blocked_reason": blocked_reason,
                    }
                )

        # Check if this instance is already running one of the usable released patches
        matched_patch: dict[str, Any] | None = None
        digest_mismatch = False
        observed_digests = sorted(obs.get("observed_digests") or set())
        missing_digest_rows = int(obs.get("missing_digest_rows") or 0)
        has_inventory_digest_conflict = len(observed_digests) > 1 or (
            len(observed_digests) == 1 and missing_digest_rows > 0
        )
        for patch in usable_patches:
            if ver == patch["replacement_version"] and parsed["purl"] == patch["replacement_purl"]:
                expected_digest = patch.get("artifact_digest")
                observed_digest = obs.get("artifact_digest")
                if has_inventory_digest_conflict:
                    digest_mismatch = True
                    blocked_candidates.append(
                        {
                            "patch_id": patch["patch_id"],
                            "replacement_purl": patch["replacement_purl"],
                            "provider": patch["provider"],
                            "provider_kind": patch["provider_kind"],
                            "blocked_reason": "conflicting_inventory_artifact_digests",
                            "observed_digests": observed_digests,
                        }
                    )
                    if expected_digest and any(d != expected_digest for d in observed_digests):
                        blocked_candidates.append(
                            {
                                "patch_id": patch["patch_id"],
                                "replacement_purl": patch["replacement_purl"],
                                "provider": patch["provider"],
                                "provider_kind": patch["provider_kind"],
                                "blocked_reason": "artifact_digest_mismatch",
                            }
                        )
                elif expected_digest and observed_digest and expected_digest != observed_digest:
                    digest_mismatch = True
                    blocked_candidates.append(
                        {
                            "patch_id": patch["patch_id"],
                            "replacement_purl": patch["replacement_purl"],
                            "provider": patch["provider"],
                            "provider_kind": patch["provider_kind"],
                            "blocked_reason": "artifact_digest_mismatch",
                        }
                    )
                elif expected_digest and not observed_digest:
                    digest_mismatch = True
                    blocked_candidates.append(
                        {
                            "patch_id": patch["patch_id"],
                            "replacement_purl": patch["replacement_purl"],
                            "provider": patch["provider"],
                            "provider_kind": patch["provider_kind"],
                            "blocked_reason": "missing_observed_artifact_digest",
                        }
                    )
                else:
                    matched_patch = patch
                    break

        # Determine staleness relative to estate snapshot_date
        stale_obs = False
        if snapshot_date != "unknown" and obs.get("observed_at") and obs["observed_at"] != "unknown":
            try:
                snap_dt = datetime.fromisoformat(snapshot_date.replace("Z", "+00:00"))
                obs_dt = datetime.fromisoformat(obs["observed_at"].replace("Z", "+00:00"))
                if (snap_dt - obs_dt).days > stale_after_days:
                    stale_obs = True
            except ValueError:
                pass

        # Conflicting feed evidence check
        has_conflict = any(
            b["blocked_reason"] == "conflicting_feed_evidence" for b in blocked_candidates
        )

        # Effective vulnerable CVEs: filter out CVEs only marked 'not_affected' when no 'affected'/'fixed' applies,
        # while NEVER treating 'not_affected' or 'under_investigation' as a patch!
        not_affected_cves = {
            v["vulnerability"].upper() for v in matching_vex if v["status"] == "not_affected"
        }
        under_investigation_cves = {
            v["vulnerability"].upper() for v in matching_vex if v["status"] == "under_investigation"
        }

        if has_conflict:
            instance_state = "unknown_evidence"
            reason = "Conflicting patch feed or VEX evidence requires analyst resolution."
            eligible = True
        elif digest_mismatch:
            instance_state = "applicable_unadopted"
            reason = "Observed package coordinate matches patch version, but artifact digest is mismatched or missing."
            eligible = True
        elif matched_patch is not None:
            instance_state = "observed_patched"
            reason = f"Observed patched artifact {matched_patch['replacement_purl']} via SBOM/build inventory."
            eligible = True
        elif usable_patches:
            instance_state = "applicable_unadopted"
            reason = f"Applicable released patch available ({usable_patches[0]['replacement_purl']}), not yet observed in this application."
            eligible = True
        else:
            instance_state = "no_known_patch"
            eligible = bool(obs["cves"])
            if blocked_candidates:
                reasons = ", ".join(sorted({b["blocked_reason"] for b in blocked_candidates}))
                reason = f"No usable released patch (blocked candidates: {reasons})."
            elif not_affected_cves or under_investigation_cves:
                reason = "No released patch; VEX not_affected / under_investigation statements do not count as patches."
            else:
                reason = "No known released patch in active feeds."

        # Exposure calculations
        addressed_cves: list[str] = []
        addressed_kev_cves: list[str] = []
        potential_cves: list[str] = []
        potential_kev_cves: list[str] = []
        residual_cves: list[str] = []

        if matched_patch is not None:
            fixed_set = {
                a.upper()
                for a in (matched_patch.get("fixed_advisories") or []) + (matched_patch.get("aliases") or [])
            }
            for cve in obs["cves"]:
                if cve.upper() in fixed_set:
                    addressed_cves.append(cve)
                    if cve in obs["kev_cves"]:
                        addressed_kev_cves.append(cve)
                else:
                    residual_cves.append(cve)
            for res_adv in matched_patch.get("residual_advisories") or []:
                if res_adv not in residual_cves:
                    residual_cves.append(res_adv)
        elif usable_patches:
            best_patch = usable_patches[0]
            fixed_set = {
                a.upper()
                for a in (best_patch.get("fixed_advisories") or []) + (best_patch.get("aliases") or [])
            }
            for cve in obs["cves"]:
                if cve.upper() in fixed_set:
                    potential_cves.append(cve)
                    if cve in obs["kev_cves"]:
                        potential_kev_cves.append(cve)
                else:
                    residual_cves.append(cve)
            for res_adv in best_patch.get("residual_advisories") or []:
                if res_adv not in residual_cves:
                    residual_cves.append(res_adv)
        else:
            residual_cves = list(obs["cves"])

        rec = {
            "instance_id": obs["instance_id"],
            "application_id": obs["application_id"],
            "project_group": obs["project_group"],
            "raw_purl": obs["raw_purl"],
            "purl": parsed["purl"],
            "ecosystem_type": eco_type,
            "ecosystem": parsed["ecosystem"],
            "library": lib_name,
            "version": ver,
            "maintenance_line": maint_line,
            "dependency_scopes": sorted(obs["dependency_scopes"]),
            "cves": obs["cves"],
            "kev_cves": obs["kev_cves"],
            "eligible": eligible,
            "instance_state": instance_state,
            "package_adoption_state": instance_state,
            "reason": reason,
            "applicable_patches": [
                {
                    "patch_id": p["patch_id"],
                    "provider": p["provider"],
                    "provider_kind": p["provider_kind"],
                    "supplier": p["supplier"],
                    "replacement_purl": p["replacement_purl"],
                    "replacement_version": p["replacement_version"],
                    "artifact_digest": p.get("artifact_digest"),
                    "fixed_advisories": p["fixed_advisories"],
                    "required_companions": p["required_companions"],
                    "provenance": p["provenance"],
                }
                for p in usable_patches
            ],
            "blocked_candidates": blocked_candidates,
            "vex_assessments": [
                {
                    "feed_id": v["feed_id"],
                    "vulnerability": v["vulnerability"],
                    "status": v["status"],
                    "supplier": v["supplier"],
                    "purl": v["purl"],
                }
                for v in matching_vex
            ],
            "matched_patch": (
                {
                    "patch_id": matched_patch["patch_id"],
                    "provider": matched_patch["provider"],
                    "provider_kind": matched_patch["provider_kind"],
                    "replacement_purl": matched_patch["replacement_purl"],
                    "artifact_digest": matched_patch.get("artifact_digest"),
                }
                if matched_patch
                else None
            ),
            "addressed_cves": addressed_cves,
            "addressed_kev_cves": addressed_kev_cves,
            "potential_cves": potential_cves,
            "potential_kev_cves": potential_kev_cves,
            "residual_cves": residual_cves,
            "observation_basis": "sbom_build_observation_not_verified_runtime",
            "stale_observation": stale_obs,
        }
        instance_records.append(rec)
        package_line_groups.setdefault((eco_type, lib_name, maint_line), []).append(rec)

    # Compute package-line adoption state (identifying 'partially_adopted' when a line has both
    # observed_patched and applicable_unadopted instances across applications)
    package_summaries: list[dict[str, Any]] = []
    for (eco_type, lib_name, maint_line), group in sorted(package_line_groups.items()):
        states = {r["instance_state"] for r in group}
        if "observed_patched" in states and "applicable_unadopted" in states:
            pkg_state = "partially_adopted"
        elif states == {"observed_patched"}:
            pkg_state = "observed_patched"
        elif "applicable_unadopted" in states:
            pkg_state = "applicable_unadopted"
        elif "unknown_evidence" in states:
            pkg_state = "unknown_evidence"
        else:
            pkg_state = "no_known_patch"

        for r in group:
            r["package_adoption_state"] = pkg_state

        app_ids = sorted({r["application_id"] for r in group})
        patched_apps = sorted({r["application_id"] for r in group if r["instance_state"] == "observed_patched"})
        unadopted_apps = sorted({r["application_id"] for r in group if r["instance_state"] == "applicable_unadopted"})
        providers = sorted(
            {
                p["provider"]
                for r in group
                for p in r["applicable_patches"]
            }
        )
        provider_kinds = sorted(
            {
                p["provider_kind"]
                for r in group
                for p in r["applicable_patches"]
            }
        )
        package_summaries.append(
            {
                "ecosystem_type": eco_type,
                "ecosystem": ECOSYSTEM_LABELS.get(eco_type, eco_type),
                "library": lib_name,
                "maintenance_line": maint_line,
                "adoption_state": pkg_state,
                "application_count": len(app_ids),
                "application_ids": app_ids,
                "observed_patched_applications": patched_apps,
                "unadopted_applications": unadopted_apps,
                "instance_count": len(group),
                "providers": providers,
                "provider_kinds": provider_kinds,
                "osera_backpatch_available": "osera" in provider_kinds,
                "addressed_cves": sorted({c for r in group for c in r["addressed_cves"]}),
                "potential_cves": sorted({c for r in group for c in r["potential_cves"]}),
                "residual_cves": sorted({c for r in group for c in r["residual_cves"]}),
            }
        )

    # Compute estate-wide deduplicated metrics with explicit numerators, denominators, and zero-instance handling
    total_apps = len(all_app_ids)
    apps_with_available_patch = sorted(
        {
            r["application_id"]
            for r in instance_records
            if r["instance_state"] in ("observed_patched", "applicable_unadopted")
        }
    )
    apps_with_observed_patch = sorted(
        {r["application_id"] for r in instance_records if r["instance_state"] == "observed_patched"}
    )
    eligible_instances = [r for r in instance_records if r["eligible"]]
    patched_eligible_instances = [
        r for r in eligible_instances if r["instance_state"] == "observed_patched"
    ]
    unknown_instances = [r for r in instance_records if r["instance_state"] == "unknown_evidence"]
    stale_instances = [r for r in instance_records if r["stale_observation"]]

    def _build_ratio_metric(
        numerator: int,
        denominator: int,
        numerator_label: str,
        denominator_label: str,
        ids: list[str],
    ) -> dict[str, Any]:
        if denominator == 0:
            return {
                "status": "not_applicable",
                "numerator": 0,
                "denominator": 0,
                "ratio": None,
                "display": f"Not applicable (0 {denominator_label})",
                "numerator_label": numerator_label,
                "denominator_label": denominator_label,
                "snapshot_date": snapshot_date,
                "ids": [],
            }
        return {
            "status": "measured",
            "numerator": numerator,
            "denominator": denominator,
            "ratio": round(numerator / denominator, 4),
            "display": f"{numerator} / {denominator} ({round((numerator / denominator) * 100, 1)}%)",
            "numerator_label": numerator_label,
            "denominator_label": denominator_label,
            "snapshot_date": snapshot_date,
            "ids": ids,
        }

    metrics = {
        "scope_id": snapshot_id,
        "snapshot_date": snapshot_date,
        "observation_basis": "sbom_build_observation_not_verified_runtime",
        "applications_with_available_patch": _build_ratio_metric(
            len(apps_with_available_patch),
            total_apps,
            "applications with an available released patch",
            "inventoried applications",
            apps_with_available_patch,
        ),
        "applications_with_observed_patch_use": _build_ratio_metric(
            len(apps_with_observed_patch),
            total_apps,
            "applications with observed patch use (SBOM/build)",
            "inventoried applications",
            apps_with_observed_patch,
        ),
        "patched_eligible_component_instances": _build_ratio_metric(
            len(patched_eligible_instances),
            len(eligible_instances),
            "patched eligible component instances",
            "eligible component instances",
            [r["instance_id"] for r in patched_eligible_instances],
        ),
        "state_counts": {
            "observed_patched": sum(1 for r in instance_records if r["package_adoption_state"] == "observed_patched"),
            "partially_adopted": sum(1 for r in instance_records if r["package_adoption_state"] == "partially_adopted"),
            "applicable_unadopted": sum(
                1 for r in instance_records if r["package_adoption_state"] == "applicable_unadopted"
            ),
            "no_known_patch": sum(1 for r in instance_records if r["package_adoption_state"] == "no_known_patch"),
            "unknown_evidence": len(unknown_instances),
        },
        "package_state_counts": {
            "observed_patched": sum(1 for p in package_summaries if p["adoption_state"] == "observed_patched"),
            "partially_adopted": sum(1 for p in package_summaries if p["adoption_state"] == "partially_adopted"),
            "applicable_unadopted": sum(1 for p in package_summaries if p["adoption_state"] == "applicable_unadopted"),
            "no_known_patch": sum(1 for p in package_summaries if p["adoption_state"] == "no_known_patch"),
            "unknown_evidence": sum(1 for p in package_summaries if p["adoption_state"] == "unknown_evidence"),
        },
        "exposure_summary": {
            "observed_remediated_cves": sorted({c for r in instance_records for c in r["addressed_cves"]}),
            "observed_remediated_kevs": sorted({c for r in instance_records for c in r["addressed_kev_cves"]}),
            "potential_reducible_cves": sorted({c for r in instance_records for c in r["potential_cves"]}),
            "potential_reducible_kevs": sorted({c for r in instance_records for c in r["potential_kev_cves"]}),
            "residual_cves": sorted({c for r in instance_records for c in r["residual_cves"]}),
        },
        "stale_observation_count": len(stale_instances),
        "unknown_observation_count": len(unknown_instances),
    }

    uncovered_cart = export_uncovered_demand_cart(instance_records, snapshot_id=snapshot_id)

    return {
        "snapshot_id": snapshot_id,
        "snapshot_date": snapshot_date,
        "feeds": catalog["feeds"],
        "feed_conflicts": catalog["feed_conflicts"],
        "ambiguous_records": catalog["ambiguous_records"],
        "metrics": metrics,
        "package_summaries": package_summaries,
        "instance_records": instance_records,
        "uncovered_demand_cart": uncovered_cart,
    }


def filter_estate_patch_records(
    evaluation: dict[str, Any],
    *,
    provider: str = "",
    feed_id: str = "",
    project_id: str = "",
    project_group: str = "",
    ecosystem: str = "",
    maintenance_line: str = "",
    advisory_id: str = "",
    adoption_state: str = "",
) -> list[dict[str, Any]]:
    """Filter instance drill-down records by provider, feed, project, group, ecosystem, line, advisory, or state."""
    records = evaluation.get("instance_records") or []
    out: list[dict[str, Any]] = []
    adv_norm = advisory_id.strip().upper()
    for rec in records:
        if project_id and rec["application_id"] != project_id:
            continue
        if project_group and rec["project_group"] != project_group:
            continue
        if ecosystem and rec["ecosystem"].lower() != ecosystem.lower() and rec["ecosystem_type"].lower() != ecosystem.lower():
            continue
        if maintenance_line and rec["maintenance_line"] != maintenance_line:
            continue
        if adoption_state and rec["package_adoption_state"] != adoption_state and rec["instance_state"] != adoption_state:
            continue
        if provider:
            prov_match = any(
                p["provider"].lower() == provider.lower() or p["provider_kind"].lower() == provider.lower()
                for p in rec["applicable_patches"]
            )
            if not prov_match:
                continue
        if feed_id:
            feed_match = any(
                prov["feed_id"] == feed_id
                for p in rec["applicable_patches"]
                for prov in p.get("provenance", [])
            )
            if not feed_match:
                continue
        if adv_norm:
            all_advs = {
                c.upper()
                for c in (rec["cves"] + rec["addressed_cves"] + rec["potential_cves"] + rec["residual_cves"])
            }
            for p in rec["applicable_patches"]:
                for a in p.get("fixed_advisories") or []:
                    all_advs.add(a.upper())
            if adv_norm not in all_advs:
                continue
        out.append(rec)
    return out


def export_uncovered_demand_cart(
    instance_records: list[dict[str, Any]],
    *,
    snapshot_id: str = "estate-default",
) -> list[dict[str, Any]]:
    """Link uncovered demand ('no_known_patch' coverage gaps) to the OSERA request-cart workflow (#29 / #41 / #42)."""
    by_coord: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in instance_records:
        if rec.get("instance_state") != "no_known_patch" or not rec.get("eligible"):
            continue
        key = (rec["ecosystem_type"], rec["library"], rec["maintenance_line"])
        if key not in by_coord:
            by_coord[key] = {
                "Action": "CREATE_PATCH_REQUEST",
                "Scope": snapshot_id,
                "Ecosystem": rec["ecosystem"],
                "Package": rec["library"],
                "MaintenanceLine": rec["maintenance_line"],
                "ObservedVersions": [],
                "AffectedApplications": [],
                "CVEs": [],
                "KEVs": [],
                "BlockedReasons": [],
            }
        item = by_coord[key]
        if rec["version"] and rec["version"] not in item["ObservedVersions"]:
            item["ObservedVersions"].append(rec["version"])
        if rec["application_id"] not in item["AffectedApplications"]:
            item["AffectedApplications"].append(rec["application_id"])
        for cve in rec.get("cves") or []:
            if cve not in item["CVEs"]:
                item["CVEs"].append(cve)
        for kev in rec.get("kev_cves") or []:
            if kev not in item["KEVs"]:
                item["KEVs"].append(kev)
        for b in rec.get("blocked_candidates") or []:
            reason = b.get("blocked_reason")
            if reason and reason not in item["BlockedReasons"]:
                item["BlockedReasons"].append(reason)
    return list(by_coord.values())


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate patch feeds and estate patch adoption (#41).")
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("data/fixtures/patch-feeds-estate-sample.json"),
        help="Path to combined patch feeds + estate snapshot fixture JSON.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write full evaluation JSON.",
    )
    parser.add_argument(
        "--write-dashboard",
        type=Path,
        default=None,
        help="Optional dashboard dataset JSON path (e.g. data/finos-sample-platform.json) to populate patch_feed_adoption.",
    )
    args = parser.parse_args()
    raw = json.loads(args.fixture.read_text(encoding="utf-8"))
    result = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.write_dashboard:
        dashboard_payload = json.loads(args.write_dashboard.read_text(encoding="utf-8"))
        dashboard_payload["patch_feed_adoption"] = result
        args.write_dashboard.write_text(json.dumps(dashboard_payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["metrics"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

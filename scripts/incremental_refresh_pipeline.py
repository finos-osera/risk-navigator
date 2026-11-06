#!/usr/bin/env python3
"""Incremental, versioned dataset refresh pipelines for FINOS, FINOS Labs, and shared risk evidence (#73).

Implements Workstreams 1–7 of finos-osera/risk-navigator#73:
- Workstream 1: Configurable collections (`data/collections/collections.json` for `finos-github-org`,
  `finos-labs`, and protected `curated_demos`) and commit/manifest-hash incremental inventory reuse.
- Workstream 2: Inventory-scoped OSV querybatch + advisory detail cache without global `all.zip`,
  cross-collection package deduplication, negative-cache expiry, non-CVE preservation, and range/unsupported
  ecosystem safety (never labeling unresolved or unsupported inputs as `clean`).
- Workstream 3: Independently refreshed shared sources (OSV query snapshot, OSERA OpenVEX, KEV/EPSS,
  OSS-risk scorecards) with conditional fetch and evidence-only reassessment mode.
- Workstream 4: Canonical semantic hashing (`content_sha256`), immutable assessment receipts, offline replay,
  and two-mode snapshot comparisons (`inventory_changes_only` vs `evidence_changes_only` vs `mixed`).
- Workstream 5 & 7: Exception-safe staged publication with `.bak` rollback, 5 MiB dataset guard, scope-shrink
  protection, and public `/data/pipeline-status.json` updates (`succeeded`, `unchanged`, `failed`, `cancelled`,
  `stale_unknown`) with allowlisted public redaction.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common import canonical_library_id, parse_library_id, split_coords
from ingest_vulns import ensure_schema, ingest_records

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_COLLECTIONS_CONFIG_PATH = ROOT_DIR / "data" / "collections" / "collections.json"
DEFAULT_PIPELINE_STATUS_PATH = ROOT_DIR / "data" / "pipeline-status.json"

VOLATILE_DATASET_META_KEYS = frozenset(
    {
        "generated_at",
        "built_at",
        "checked_at",
        "last_checked_at",
        "run_id",
        "run_url",
        "content_sha256",
        "snapshot_id",
    }
)

EXACT_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z_.+-]*$")
UNRESOLVED_RANGE_MARKERS_RE = re.compile(r"[\^~*><=|$\s]|^(?:latest|main|master|unspecified|workspace:.*)$", re.IGNORECASE)
SECRET_REDACTION_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|Bearer\s+[A-Za-z0-9._-]+|token=[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)


def _parse_iso_dt(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _sha256_json(data: Any) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ============================================================================
# Workstream 1 — Configurable Collections & Incremental Inventory
# ============================================================================


def load_collections_config(config_path: Path = DEFAULT_COLLECTIONS_CONFIG_PATH) -> dict[str, Any]:
    """Load and validate the versioned collections configuration (#73 Workstream 1)."""
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if str(payload.get("schema_version")) != "1":
        raise ValueError(f"Unsupported collections config schema_version: {payload.get('schema_version')}")
    collections_by_id = {c["collection_id"]: c for c in (payload.get("collections") or [])}
    if "finos-github-org" not in collections_by_id or "finos-labs" not in collections_by_id:
        raise ValueError("Collections config must define both 'finos-github-org' and 'finos-labs'.")
    return payload


def run_incremental_inventory_scan(
    collection_config: dict[str, Any],
    discovered_repositories: list[dict[str, Any]],
    previous_inventory_cache: dict[str, Any] | None = None,
    *,
    extractor_version: str = "extract_org/2026.11.1",
    checked_at: str = "2026-11-06T00:00:00Z",
    max_allowed_shrink_ratio: float = 0.20,
    allow_shrink: bool = False,
) -> dict[str, Any]:
    """Execute an incremental repository inventory pass with commit & dependency-file hash reuse (#73 Workstream 1).

    Enforces:
    - Unchanged commit OR README-only change (where `dependency_files_sha256`, `extractor_version`, and
      `config_fingerprint` match cache) reuses the cached dependency edges without re-extracting!
    - Parser/extractor or config version change invalidates cached extraction and forces re-extraction.
    - Distinguishes `branch_checked_at` from `dependency_extracted_at`.
    - Tracks repository additions, removals, renames, inaccessible repos, and manifest truncation.
    - Fails closed if repository scan failures occur or scope shrinks beyond `max_allowed_shrink_ratio`
      unless `allow_shrink=True`.
    """
    cache = previous_inventory_cache or {}
    cached_repos: dict[str, dict[str, Any]] = cache.get("repositories") or {}
    prev_repo_By_id: dict[str, str] = {
        str(r.get("repo_id")): repo_name
        for repo_name, r in cached_repos.items()
        if isinstance(r, dict) and r.get("repo_id")
    }

    config_fingerprint = _sha256_json(
        {
            "collection_id": collection_config.get("collection_id"),
            "supported_ecosystems": collection_config.get("supported_ecosystems"),
            "scan_limits": collection_config.get("scan_limits"),
            "default_branch_only": collection_config.get("default_branch_only", True),
        }
    )
    max_manifests = int((collection_config.get("scan_limits") or {}).get("max_manifests_per_repo", 32))
    supported_ecosystems = set(collection_config.get("supported_ecosystems") or ["maven", "npm", "pypi"])

    new_cached_repos: dict[str, dict[str, Any]] = {}
    all_edges: list[dict[str, Any]] = []
    added_repos: list[str] = []
    removed_repos: list[str] = []
    renamed_repos: list[dict[str, str]] = []
    inaccessible_repos: list[str] = []
    failed_repos: list[str] = []
    truncated_repos: list[str] = []

    cache_hits = 0
    cache_misses = 0

    current_names: set[str] = set()
    for repo in discovered_repositories:
        if repo.get("archived") and not collection_config.get("include_archived", False):
            continue
        if repo.get("fork") and not collection_config.get("include_forks", False):
            continue
        name = str(repo.get("full_name") or repo.get("name") or "").strip()
        if not name or name in (collection_config.get("excluded_repositories") or []):
            continue
        current_names.add(name)

        repo_id = str(repo.get("repo_id") or name)
        if repo_id in prev_repo_By_id and prev_repo_By_id[repo_id] != name:
            renamed_repos.append({"from": prev_repo_By_id[repo_id], "to": name, "repo_id": repo_id})

        status = str(repo.get("status") or "ok").strip().lower()
        if status == "inaccessible":
            inaccessible_repos.append(name)
            continue
        if status == "failed":
            failed_repos.append(name)
            continue

        ref = str(repo.get("default_branch") or repo.get("ref") or "main")
        commit_sha = str(repo.get("commit_sha") or "").strip()
        dep_files = repo.get("dependency_files") if isinstance(repo.get("dependency_files"), list) else []
        if len(dep_files) > max_manifests:
            truncated_repos.append(name)
            dep_files = dep_files[:max_manifests]

        dep_files_hash = _sha256_json(
            [{"path": f.get("path"), "sha256": f.get("sha256")} for f in sorted(dep_files, key=lambda x: str(x.get("path")))]
        )

        prev_entry = cached_repos.get(name) or (
            cached_repos.get(prev_repo_By_id[repo_id]) if repo_id in prev_repo_By_id else None
        )
        if prev_entry is None and repo_id not in prev_repo_By_id:
            added_repos.append(name)

        can_reuse = (
            isinstance(prev_entry, dict)
            and prev_entry.get("extractor_version") == extractor_version
            and prev_entry.get("config_fingerprint") == config_fingerprint
            and (
                prev_entry.get("commit_sha") == commit_sha
                or prev_entry.get("dependency_files_sha256") == dep_files_hash
            )
        )

        if can_reuse:
            cache_hits += 1
            extracted_at = str(prev_entry["dependency_extracted_at"])
            repo_edges = copy.deepcopy(prev_entry.get("edges") or [])
        else:
            cache_misses += 1
            extracted_at = checked_at
            repo_edges = []
            for raw_edge in repo.get("extracted_edges") or []:
                eco = str(raw_edge.get("ecosystem") or "").lower()
                pkg = str(raw_edge.get("package") or "").strip()
                ver = str(raw_edge.get("version") or "").strip()
                is_unresolved = bool(UNRESOLVED_RANGE_MARKERS_RE.search(ver)) or not bool(EXACT_VERSION_RE.match(ver))
                if eco not in supported_ecosystems:
                    resolution_state = "unsupported_ecosystem"
                elif is_unresolved:
                    resolution_state = "unresolved_range"
                else:
                    resolution_state = "exact_version"
                repo_edges.append(
                    {
                        "consumer_id": name,
                        "ecosystem": eco,
                        "package": pkg,
                        "version": ver,
                        "library_id": canonical_library_id(f"{eco}||{pkg}|{ver}") if ":" not in pkg else canonical_library_id(f"{eco}|{pkg.replace(':', '|')}|{ver}"),
                        "direct": bool(raw_edge.get("direct", True)),
                        "resolution_state": resolution_state,
                    }
                )

        new_cached_repos[name] = {
            "repo_id": repo_id,
            "full_name": name,
            "ref": ref,
            "commit_sha": commit_sha,
            "dependency_files_sha256": dep_files_hash,
            "extractor_version": extractor_version,
            "config_fingerprint": config_fingerprint,
            "branch_checked_at": checked_at,
            "dependency_extracted_at": extracted_at,
            "truncated": name in truncated_repos,
            "edges": repo_edges,
        }
        all_edges.extend(repo_edges)

    renamed_sources = {r["from"] for r in renamed_repos}
    for old_name in cached_repos:
        if old_name not in current_names and old_name not in renamed_sources:
            removed_repos.append(old_name)

    if failed_repos:
        raise RuntimeError(f"Repository scan failed for {failed_repos}; refusing to replace published inventory.")

    prev_count = len(cached_repos)
    curr_count = len(new_cached_repos)
    shrink_ratio = ((prev_count - curr_count) / prev_count) if prev_count > 0 and curr_count < prev_count else 0.0
    if shrink_ratio > max_allowed_shrink_ratio and not allow_shrink:
        raise RuntimeError(
            f"Unexpected repository scope shrink ({prev_count} -> {curr_count}, ratio={shrink_ratio:.2f} > {max_allowed_shrink_ratio:.2f}); refusing to publish."
        )

    inventory_content_hash = _sha256_json(
        {
            "collection_id": collection_config.get("collection_id"),
            "repos": {
                k: {
                    "commit_sha": v["commit_sha"],
                    "dependency_files_sha256": v["dependency_files_sha256"],
                    "edges": v["edges"],
                }
                for k, v in sorted(new_cached_repos.items())
            },
        }
    )

    return {
        "collection_id": collection_config.get("collection_id"),
        "inventory_snapshot_id": f"{collection_config.get('collection_id')}-inv-{inventory_content_hash[:12]}",
        "inventory_content_sha256": inventory_content_hash,
        "branch_checked_at": checked_at,
        "dependency_extracted_at": max(
            (v["dependency_extracted_at"] for v in new_cached_repos.values()),
            default=checked_at,
        ),
        "repositories": new_cached_repos,
        "edges": all_edges,
        "membership_changes": {
            "added": sorted(added_repos),
            "removed": sorted(removed_repos),
            "renamed": renamed_repos,
            "inaccessible": sorted(inaccessible_repos),
            "truncated": sorted(truncated_repos),
            "shrink_ratio": round(shrink_ratio, 4),
        },
        "measurements": {
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "total_repositories": curr_count,
            "total_edges": len(all_edges),
        },
    }


# ============================================================================
# Workstream 2 — Inventory-Scoped Vulnerability Evidence (No Global all.zip)
# ============================================================================


def resolve_inventory_scoped_osv_across_collections(
    collection_inventories: list[dict[str, Any]],
    osv_client: Any,
    osv_cache: dict[str, Any] | None = None,
    *,
    queried_at: str = "2026-11-06T00:05:00Z",
    security_freshness_ttl_seconds: int = 86400,
    batch_size: int = 100,
    sqlite_db_path: Path | None = None,
) -> dict[str, Any]:
    """Resolve OSV vulnerabilities across collections without downloading global `all.zip` (#73 Workstream 2).

    Enforces:
    - Deduplicates shared exact package/versions across multiple collections so OSV is queried ONCE per unique
      `(ecosystem, package, version)` while attributing results accurately to each collection.
    - Follows per-query `next_page_token` pagination and fails closed on truncated/malformed batch responses.
    - Requeries unchanged package versions when `security_freshness_ttl_seconds` expires (including negative
      cache entries with `vulns: []`) so newly disclosed advisories on unchanged inventory are detected.
    - Fetches `/v1/vulns/<id>` detail ONLY when absent from `advisory_details_cache` or when `modified` changed.
    - Handles withdrawn advisories, aliases, declared ranges vs exact versions (never labeling unresolved ranges
      or unsupported ecosystems as `clean`), and preserves non-CVE advisories (`non_cve_advisories`).
    """
    cache = copy.deepcopy(osv_cache) if isinstance(osv_cache, dict) else {}
    version_query_cache: dict[str, dict[str, Any]] = cache.setdefault("version_queries", {})
    advisory_details_cache: dict[str, dict[str, Any]] = cache.setdefault("advisory_details", {})

    now_dt = _parse_iso_dt(queried_at) or datetime.now(timezone.utc)
    ecosystem_map = {"npm": "npm", "maven": "Maven", "pypi": "PyPI"}

    # Collect unique exact package/versions across all collections and track unresolved/unsupported edges
    unique_exact_queries: dict[str, dict[str, Any]] = {}
    collection_edge_status: dict[str, dict[str, Any]] = {}

    for inv in collection_inventories:
        cid = str(inv["collection_id"])
        unresolved_edges: list[dict[str, Any]] = []
        unsupported_edges: list[dict[str, Any]] = []
        exact_lids: set[str] = set()

        for edge in inv.get("edges") or []:
            res_state = edge.get("resolution_state")
            if res_state == "unsupported_ecosystem":
                unsupported_edges.append({**edge, "assessment_status": "unknown_unsupported_ecosystem"})
                continue
            if res_state == "unresolved_range":
                unresolved_edges.append({**edge, "assessment_status": "unknown_unresolved_range"})
                continue

            lid = str(edge["library_id"])
            exact_lids.add(lid)
            if lid not in unique_exact_queries:
                ns, meta, proj, ver = parse_library_id(lid)
                pkg_name = f"{meta}:{proj}" if ns == "maven" else (f"{meta}/{proj}" if meta else proj)
                unique_exact_queries[lid] = {
                    "library_id": lid,
                    "query": {"package": {"ecosystem": ecosystem_map[ns], "name": pkg_name}, "version": ver},
                }

        collection_edge_status[cid] = {
            "exact_library_ids": sorted(exact_lids),
            "unresolved_range_edges": unresolved_edges,
            "unsupported_ecosystem_edges": unsupported_edges,
        }

    # Determine which unique exact package/versions require a fresh OSV querybatch call
    pending_items: list[tuple[str, dict[str, Any]]] = []
    query_cache_hits = 0
    for lid, item in sorted(unique_exact_queries.items()):
        cached_q = version_query_cache.get(lid)
        if isinstance(cached_q, dict):
            checked_dt = _parse_iso_dt(cached_q.get("checked_at"))
            if checked_dt and (now_dt - checked_dt).total_seconds() < security_freshness_ttl_seconds:
                query_cache_hits += 1
                continue
        pending_items.append((lid, item["query"]))

    batch_request_count = 0
    detail_request_count = 0

    # Query OSV in bounded batches, following next_page_token pagination
    for i in range(0, len(pending_items), batch_size):
        current_batch = pending_items[i : i + batch_size]
        accumulated_vulns: dict[str, list[dict[str, str]]] = {lid: [] for lid, _ in current_batch}
        to_fetch = current_batch
        while to_fetch:
            batch_request_count += 1
            resp = osv_client.querybatch([q for _, q in to_fetch])
            results = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(results, list) or len(results) != len(to_fetch):
                raise RuntimeError("Incomplete or malformed OSV querybatch response.")
            next_page: list[tuple[str, dict[str, Any]]] = []
            for (lid, q), res in zip(to_fetch, results):
                if not isinstance(res, dict):
                    raise RuntimeError(f"Malformed OSV result entry for {lid}")
                for v in res.get("vulns") or []:
                    if isinstance(v, dict) and v.get("id"):
                        accumulated_vulns[lid].append(
                            {"id": str(v["id"]), "modified": str(v.get("modified") or "")}
                        )
                if res.get("next_page_token"):
                    next_page.append((lid, {**q, "page_token": res["next_page_token"]}))
            to_fetch = next_page

        for lid, _ in current_batch:
            version_query_cache[lid] = {
                "checked_at": queried_at,
                "vulns": accumulated_vulns[lid],
                "response_sha256": _sha256_json(accumulated_vulns[lid]),
            }

    # Collect all referenced advisory IDs and their latest modified timestamps across active queries
    needed_advisories: dict[str, str] = {}
    matched_lids_by_adv: dict[str, set[str]] = {}
    for lid in unique_exact_queries:
        q_entry = version_query_cache.get(lid) or {}
        for v in q_entry.get("vulns") or []:
            vid = str(v["id"])
            mod = str(v.get("modified") or "")
            if vid not in needed_advisories or mod > needed_advisories[vid]:
                needed_advisories[vid] = mod
            matched_lids_by_adv.setdefault(vid, set()).add(lid)

    detail_cache_hits = 0
    for vid, expected_mod in sorted(needed_advisories.items()):
        cached_det = advisory_details_cache.get(vid)
        if (
            isinstance(cached_det, dict)
            and cached_det.get("record")
            and str(cached_det["record"].get("modified") or "") == expected_mod
            and expected_mod != ""
        ):
            detail_cache_hits += 1
            continue
        detail_request_count += 1
        rec = osv_client.get_vuln(vid)
        if not isinstance(rec, dict) or rec.get("id") != vid:
            raise RuntimeError(f"Invalid OSV advisory detail payload for {vid}")
        advisory_details_cache[vid] = {
            "retrieved_at": queried_at,
            "modified": str(rec.get("modified") or ""),
            "sha256": _sha256_json(rec),
            "record": rec,
        }

    # Filter out withdrawn advisories, verify affected range applicability, and separate CVE vs non-CVE advisories
    active_records_for_sqlite: list[dict[str, Any]] = []
    findings_by_lid: dict[str, list[dict[str, Any]]] = {lid: [] for lid in unique_exact_queries}
    withdrawn_advisory_ids: list[str] = []

    for vid, lids in sorted(matched_lids_by_adv.items()):
        rec = copy.deepcopy(advisory_details_cache[vid]["record"])
        if rec.get("withdrawn"):
            withdrawn_advisory_ids.append(vid)
            continue

        # Check if advisory was corrected to exclude a previously matched version
        explicitly_excluded = set(rec.get("excluded_versions") or [])
        valid_lids = {
            lid for lid in lids if parse_library_id(lid)[3] not in explicitly_excluded
        }
        if not valid_lids:
            continue

        aliases = [str(a) for a in (rec.get("aliases") or []) if str(a).strip()]
        all_ids = [vid, *aliases]
        cve_ids = sorted({i.upper() for i in all_ids if i.upper().startswith("CVE-")})

        for lid in sorted(valid_lids):
            findings_by_lid[lid].append(
                {
                    "advisory_id": vid,
                    "cve_aliases": cve_ids,
                    "has_cve_alias": len(cve_ids) > 0,
                    "aliases": aliases,
                    "modified": rec.get("modified"),
                    "summary": rec.get("summary") or "",
                }
            )

        # Prepare record for SQLite materialization
        for affected in rec.get("affected") or []:
            pkg = affected.get("package") or {}
            coords = split_coords(pkg.get("ecosystem", ""), pkg.get("name", ""))
            obs_vers = [parse_library_id(l)[3] for l in valid_lids if parse_library_id(l)[:3] == coords]
            affected["versions"] = sorted(set(affected.get("versions") or []) | set(obs_vers))
        active_records_for_sqlite.append(rec)

    if sqlite_db_path is not None:
        sqlite_db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(sqlite_db_path)
        try:
            ensure_schema(conn)
            conn.execute("DELETE FROM vuln_version_edges")
            ingest_records(conn, active_records_for_sqlite, progress_every=0)
        finally:
            conn.close()

    # Attribute results back per collection
    per_collection_results: dict[str, dict[str, Any]] = {}
    for inv in collection_inventories:
        cid = str(inv["collection_id"])
        st = collection_edge_status[cid]
        cve_findings: list[dict[str, Any]] = []
        non_cve_findings: list[dict[str, Any]] = []
        clean_exact_count = 0

        for lid in st["exact_library_ids"]:
            f_list = findings_by_lid.get(lid) or []
            if not f_list:
                clean_exact_count += 1
            for f in f_list:
                if f["has_cve_alias"]:
                    cve_findings.append({"library_id": lid, **f})
                else:
                    non_cve_findings.append({"library_id": lid, **f})

        per_collection_results[cid] = {
            "collection_id": cid,
            "exact_package_versions_evaluated": len(st["exact_library_ids"]),
            "clean_exact_package_versions": clean_exact_count,
            "cve_findings": cve_findings,
            "non_cve_findings": non_cve_findings,
            "viewer_cve_limitation_note": (
                "Non-CVE advisories (e.g. GHSA/PYSEC without a CVE alias) are preserved in collection evidence "
                "so packages without a CVE alias are never labeled zero-risk."
            ),
            "unresolved_range_edges": st["unresolved_range_edges"],
            "unsupported_ecosystem_edges": st["unsupported_ecosystem_edges"],
        }

    osv_snapshot_hash = _sha256_json(
        {
            "queries": {k: version_query_cache[k]["response_sha256"] for k in sorted(unique_exact_queries)},
            "advisories": {k: advisory_details_cache[k]["sha256"] for k in sorted(needed_advisories)},
        }
    )

    return {
        "osv_snapshot_id": f"osv-query-{osv_snapshot_hash[:12]}",
        "osv_snapshot_sha256": osv_snapshot_hash,
        "queried_at": queried_at,
        "unique_exact_packages_queried_across_collections": len(unique_exact_queries),
        "withdrawn_advisories_filtered": withdrawn_advisory_ids,
        "per_collection": per_collection_results,
        "updated_cache": cache,
        "measurements": {
            "osv_batch_requests": batch_request_count,
            "osv_detail_requests": detail_request_count,
            "query_cache_hits": query_cache_hits,
            "detail_cache_hits": detail_cache_hits,
        },
    }


# ============================================================================
# Workstream 4 — Canonical Hashing, Assessment Receipts & Snapshot Comparisons
# ============================================================================


def compute_canonical_assessment_sha256(dataset: dict[str, Any]) -> str:
    """Compute a deterministic content SHA-256 excluding volatile run timestamps (#73 Workstream 4).

    Ensures identical semantic inventory + vulnerability + patch evidence does NOT produce a new content
    version or daily data-only PR churn solely because a check/build timestamp changed.
    """
    cleaned = copy.deepcopy(dataset)
    if isinstance(cleaned.get("meta"), dict):
        for k in VOLATILE_DATASET_META_KEYS:
            cleaned["meta"].pop(k, None)
    return _sha256_json(cleaned)


def build_assessment_receipt(
    *,
    collection_id: str,
    dataset: dict[str, Any],
    inventory_snapshot_id: str,
    evidence_snapshot_ids: dict[str, str],
    sources: list[dict[str, Any]],
    artifacts: list[dict[str, str]],
    collector_commit: str = "e1b8aa18333ccdf84be588dfa620876a3a2ad8da",
    methodology_version: str = "2026.11-incremental-v1",
    generated_at: str = "2026-11-06T00:10:00Z",
) -> dict[str, Any]:
    """Build and validate the immutable assessment receipt contract (#73 Workstream 4)."""
    content_sha256 = compute_canonical_assessment_sha256(dataset)
    snapshot_id = f"{collection_id}-{content_sha256[:12]}"
    receipt = {
        "schema_version": "1",
        "collection_id": collection_id,
        "snapshot_id": snapshot_id,
        "content_sha256": content_sha256,
        "generated_at": generated_at,
        "inventory_snapshot_id": inventory_snapshot_id,
        "evidence_snapshot_ids": copy.deepcopy(evidence_snapshot_ids),
        "collector_commit": collector_commit,
        "methodology_version": methodology_version,
        "coverage": copy.deepcopy((dataset.get("meta") or {}).get("coverage") or {}),
        "sources": copy.deepcopy(sources),
        "artifacts": copy.deepcopy(artifacts),
    }
    validate_assessment_receipt(receipt, dataset)
    return receipt


def validate_assessment_receipt(receipt: dict[str, Any], dataset: dict[str, Any] | None = None) -> None:
    """Validate receipt schema, source timestamps/digests, and canonical dataset hash (#73 Workstream 4)."""
    if str(receipt.get("schema_version")) != "1":
        raise ValueError("Invalid receipt schema_version; expected '1'.")
    for req_field in (
        "collection_id",
        "snapshot_id",
        "content_sha256",
        "generated_at",
        "inventory_snapshot_id",
        "evidence_snapshot_ids",
        "collector_commit",
        "methodology_version",
    ):
        if not receipt.get(req_field):
            raise ValueError(f"Assessment receipt missing required field '{req_field}'.")

    for src in receipt.get("sources") or []:
        if not isinstance(src, dict) or not src.get("name") or not src.get("sha256") or not src.get("retrieved_at"):
            raise ValueError(f"Invalid source provenance entry in receipt: {src}")

    if dataset is not None:
        expected_hash = compute_canonical_assessment_sha256(dataset)
        if receipt["content_sha256"] != expected_hash:
            raise ValueError(
                f"Receipt content_sha256 mismatch: receipt={receipt['content_sha256']} vs dataset={expected_hash}"
            )


def compare_assessment_snapshots(
    baseline_receipt: dict[str, Any],
    baseline_dataset: dict[str, Any],
    candidate_receipt: dict[str, Any],
    candidate_dataset: dict[str, Any],
) -> dict[str, Any]:
    """Compare two assessment snapshots with explicit attribution modes (#73 Workstream 6).

    Modes:
    1. `inventory_changes_only`: inventory changed under identical evidence snapshots and methodology.
    2. `evidence_changes_only`: vulnerability/patch evidence changed against identical inventory and methodology.
    3. `no_semantic_change`: both inventory and evidence (and content_sha256) are unchanged.
    4. `mixed_or_methodology_changes`: both inventory and evidence (or methodology_version) changed;
       explicitly labeled so score movement is never falsely attributed solely to repository code changes.
    """
    inv_changed = baseline_receipt["inventory_snapshot_id"] != candidate_receipt["inventory_snapshot_id"]
    ev_changed = baseline_receipt["evidence_snapshot_ids"] != candidate_receipt["evidence_snapshot_ids"]
    meth_changed = baseline_receipt["methodology_version"] != candidate_receipt["methodology_version"]

    if not inv_changed and not ev_changed and not meth_changed:
        mode = "no_semantic_change"
    elif inv_changed and not ev_changed and not meth_changed:
        mode = "inventory_changes_only"
    elif ev_changed and not inv_changed and not meth_changed:
        mode = "evidence_changes_only"
    else:
        mode = "mixed_or_methodology_changes"

    old_libs = {lib["id"]: lib for lib in (baseline_dataset.get("libraries") or []) if isinstance(lib, dict) and lib.get("id")}
    new_libs = {lib["id"]: lib for lib in (candidate_dataset.get("libraries") or []) if isinstance(lib, dict) and lib.get("id")}

    added_vuln_libs = sorted(set(new_libs) - set(old_libs))
    resolved_vuln_libs = sorted(set(old_libs) - set(new_libs))

    old_cves = {c["cve_id"] for lib in old_libs.values() for c in (lib.get("cves") or []) if isinstance(c, dict) and c.get("cve_id")}
    new_cves = {c["cve_id"] for lib in new_libs.values() for c in (lib.get("cves") or []) if isinstance(c, dict) and c.get("cve_id")}

    return {
        "comparison_mode": mode,
        "baseline_snapshot_id": baseline_receipt["snapshot_id"],
        "candidate_snapshot_id": candidate_receipt["snapshot_id"],
        "inventory_changed": inv_changed,
        "evidence_changed": ev_changed,
        "methodology_changed": meth_changed,
        "newly_affected_libraries": added_vuln_libs,
        "resolved_libraries": resolved_vuln_libs,
        "newly_observed_cves": sorted(new_cves - old_cves),
        "resolved_cves": sorted(old_cves - new_cves),
    }


# ============================================================================
# Workstream 5 & 7 — Safe Publication with Rollback & Public Pipeline Status
# ============================================================================


def publish_collection_artifacts_safely(
    *,
    dataset: dict[str, Any],
    coverage_report: dict[str, Any],
    receipt: dict[str, Any],
    dataset_dest: Path,
    coverage_dest: Path,
    receipt_dest: Path,
    manifest_path: Path | None = None,
    max_dataset_bytes: int = 5 * 1024 * 1024,
    max_report_bytes: int = 256 * 1024,
    inject_mid_publish_failure: bool = False,
) -> dict[str, Any]:
    """Validate and publish collection artifacts before updating pointers, with `.bak` exception rollback (#73 Workstream 5).

    Note on rollback guarantees: Sequential file replacement with `.tmp` staging and `.bak` restoration
    protects against Python-level validation, I/O, or size-limit exceptions during publication, preserving
    the last valid published snapshot; it is not a kernel-atomic multi-file transaction across hard OS crashes.
    """
    validate_assessment_receipt(receipt, dataset)

    dataset_bytes = (json.dumps(dataset, separators=(",", ":")) + "\n").encode("utf-8")
    report_bytes = (json.dumps(coverage_report, indent=2) + "\n").encode("utf-8")
    receipt_bytes = (json.dumps(receipt, indent=2) + "\n").encode("utf-8")

    if len(dataset_bytes) > max_dataset_bytes:
        raise RuntimeError(f"Dataset size {len(dataset_bytes)} exceeds limit {max_dataset_bytes}; aborting publication.")
    if len(report_bytes) > max_report_bytes:
        raise RuntimeError(f"Coverage report size {len(report_bytes)} exceeds limit {max_report_bytes}; aborting publication.")

    targets = [
        (dataset_dest, dataset_bytes),
        (coverage_dest, report_bytes),
        (receipt_dest, receipt_bytes),
    ]
    backups: list[tuple[Path, Path]] = []
    temps: list[Path] = []

    try:
        for dest, payload in targets:
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = dest.with_suffix(dest.suffix + ".tmp")
            tmp_path.write_bytes(payload)
            temps.append(tmp_path)

        for idx, (dest, _) in enumerate(targets):
            if inject_mid_publish_failure and idx == 1:
                raise RuntimeError("Injected mid-publication failure after writing first artifact.")
            if dest.exists():
                bak_path = dest.with_suffix(dest.suffix + ".bak")
                shutil.copy2(dest, bak_path)
                backups.append((dest, bak_path))
            dest.with_suffix(dest.suffix + ".tmp").replace(dest)

        if manifest_path is not None and manifest_path.exists():
            manifest_bak = manifest_path.with_suffix(manifest_path.suffix + ".bak")
            shutil.copy2(manifest_path, manifest_bak)
            backups.append((manifest_path, manifest_bak))
            manifest_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
            rel_url = f"../data/{dataset_dest.name}"
            matched = next((e for e in (manifest_doc.get("datasets") or []) if e.get("url") == rel_url), None)
            if matched is None:
                manifest_doc.setdefault("datasets", []).append(
                    {
                        "label": receipt["collection_id"],
                        "url": rel_url,
                        "snapshot_id": receipt["snapshot_id"],
                        "content_sha256": receipt["content_sha256"],
                    }
                )
            else:
                matched["snapshot_id"] = receipt["snapshot_id"]
                matched["content_sha256"] = receipt["content_sha256"]
            manifest_path.write_text(json.dumps(manifest_doc, indent=2) + "\n", encoding="utf-8")

        for _, bak_path in backups:
            bak_path.unlink(missing_ok=True)
    except Exception:
        for tmp_path in temps:
            tmp_path.unlink(missing_ok=True)
        for orig_path, bak_path in reversed(backups):
            if bak_path.exists():
                bak_path.replace(orig_path)
        raise

    return {
        "published": True,
        "snapshot_id": receipt["snapshot_id"],
        "content_sha256": receipt["content_sha256"],
        "dataset_bytes": len(dataset_bytes),
    }


def sanitize_public_failure_summary(raw_message: str | None) -> str | None:
    """Redact credentials, tokens, and local filesystem paths from public status failure summaries (#73 Workstream 7)."""
    if not raw_message:
        return None
    msg = SECRET_REDACTION_RE.sub("[REDACTED_CREDENTIAL]", str(raw_message).strip())
    msg = re.sub(r"/Users/[^\s:]+", "[REDACTED_PATH]", msg)
    return msg[:240]


def update_pipeline_status_document(
    status_doc_or_path: dict[str, Any] | Path,
    *,
    collection_id: str,
    attempt: dict[str, Any],
    validated_candidate: dict[str, Any] | None = None,
    promote_to_published: bool = False,
    pending_pr_url: str | None = None,
    failure_summary: str | None = None,
    measurements: dict[str, Any] | None = None,
    checked_at: str = "2026-11-06T00:15:00Z",
    stale_running_ttl_seconds: int = 7200,
) -> dict[str, Any]:
    """Update the shared public `/data/pipeline-status.json` artifact safely (#73 Workstream 7).

    Enforces:
    - Distinguishes `latest_attempt`, `latest_validated_candidate`, and `currently_published_snapshot`.
    - A failed attempt preserves `currently_published_snapshot` (`previous_valid_snapshot_retained: True`).
    - A validated candidate awaiting PR review sets `publication_state = 'refresh_succeeded_pr_awaiting_review'`
      without overwriting `currently_published_snapshot` until merged (`promote_to_published=True`).
    - Reconciles stale `running` attempts older than `stale_running_ttl_seconds` to `stale_unknown`.
    - Redacts credentials and private paths from `failure_summary`.
    """
    if isinstance(status_doc_or_path, Path):
        doc = json.loads(status_doc_or_path.read_text(encoding="utf-8"))
    else:
        doc = copy.deepcopy(status_doc_or_path)

    now_dt = _parse_iso_dt(checked_at) or datetime.now(timezone.utc)
    doc["checked_at"] = checked_at
    doc["generated_at"] = checked_at

    pipelines = doc.setdefault("pipelines", [])
    target = next((p for p in pipelines if p.get("collection_id") == collection_id), None)
    if target is None:
        target = {
            "pipeline_id": f"refresh-{collection_id}",
            "collection_id": collection_id,
            "friendly_name": collection_id,
            "publication_state": "unknown",
            "pending_pr_url": None,
            "previous_valid_snapshot_retained": False,
            "failure_summary": None,
            "latest_attempt": None,
            "latest_validated_candidate": None,
            "currently_published_snapshot": None,
            "measurements": {},
        }
        pipelines.append(target)

    # Reconcile stale running records across all pipelines (#73 Workstream 7)
    for pipe in pipelines:
        la = pipe.get("latest_attempt")
        if isinstance(la, dict) and la.get("outcome") == "running":
            started_dt = _parse_iso_dt(la.get("started_at"))
            if started_dt and (now_dt - started_dt).total_seconds() > stale_running_ttl_seconds:
                la["outcome"] = "stale_unknown"
                pipe["failure_summary"] = "Previous running attempt exceeded heartbeat TTL without reporting completion."

    outcome = str(attempt.get("outcome") or "unknown").strip().lower()
    target["latest_attempt"] = {
        "run_id": attempt.get("run_id"),
        "run_url": attempt.get("run_url"),
        "trigger": attempt.get("trigger") or "schedule",
        "code_sha": attempt.get("code_sha"),
        "started_at": attempt.get("started_at"),
        "completed_at": attempt.get("completed_at"),
        "outcome": outcome,
    }
    if measurements:
        target["measurements"] = copy.deepcopy(measurements)

    if outcome == "failed" or outcome == "cancelled":
        target["failure_summary"] = sanitize_public_failure_summary(failure_summary or f"Pipeline attempt {outcome}.")
        target["previous_valid_snapshot_retained"] = target.get("currently_published_snapshot") is not None
        if target.get("currently_published_snapshot") is not None:
            target["publication_state"] = "previous_snapshot_retained_after_failure"
        else:
            target["publication_state"] = "failed_no_published_snapshot"
    elif outcome == "unchanged":
        target["failure_summary"] = None
        target["previous_valid_snapshot_retained"] = True
        if target.get("currently_published_snapshot") is not None:
            target["publication_state"] = "published_checked_unchanged"
    elif outcome == "succeeded":
        target["failure_summary"] = None
        if validated_candidate is not None:
            target["latest_validated_candidate"] = copy.deepcopy(validated_candidate)
        if promote_to_published and validated_candidate is not None:
            target["currently_published_snapshot"] = {
                **copy.deepcopy(validated_candidate),
                "published_at": checked_at,
            }
            target["publication_state"] = "published"
            target["pending_pr_url"] = None
            target["previous_valid_snapshot_retained"] = True
        else:
            target["publication_state"] = "refresh_succeeded_pr_awaiting_review"
            target["pending_pr_url"] = pending_pr_url
            target["previous_valid_snapshot_retained"] = target.get("currently_published_snapshot") is not None

    return doc

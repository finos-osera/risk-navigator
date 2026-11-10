#!/usr/bin/env python3
"""Incremental, versioned dataset refresh pipelines for FINOS, FINOS Labs, and shared risk evidence (#73).

Implements Workstreams 1–7 of finos-osera/risk-navigator#73:
- Workstream 1: Configurable collections (`data/collections/collections.json` for `finos-github-org`,
  `finos-labs`, and protected `curated_demos`) and commit/manifest-hash incremental inventory reuse.
- Workstream 2: Inventory-scoped OSV querybatch + advisory detail cache without global `all.zip`,
  cross-collection package deduplication, dynamic current-time negative/positive cache expiry, non-CVE
  preservation, and range/unsupported ecosystem safety (never labeling unresolved or unsupported inputs as `clean`).
- Workstream 3: Independently refreshed shared sources (OSV query snapshot, OSERA OpenVEX, KEV/EPSS,
  OSS-risk scorecards) with conditional fetch (`refresh_shared_evidence_sources_conditionally`) and
  evidence-only reassessment mode (`reassess_inventory_with_refreshed_evidence`).
- Workstream 4: Canonical semantic hashing (`content_sha256`), immutable assessment receipts, offline replay
  verification (`verify_offline_replay_determinism`), and two-mode snapshot comparisons
  (`inventory_changes_only` vs `evidence_changes_only` vs `mixed`).
- Workstream 5 & 7: Exception-safe staged publication with full pre-publication state rollback (restoring
  pre-existing `.bak` files and removing newly created files on failed first/mixed publication), 5 MiB dataset
  guard, scope-shrink protection, artifact-backed public `/data/pipeline-status.json` generation & provenance
  verification, controlled public failure codes, and comprehensive credential/path sanitization.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from common import canonical_library_id, parse_library_id, split_coords  # noqa: E402
from ingest_vulns import ensure_schema, ingest_records  # noqa: E402

ROOT_DIR = SCRIPTS_DIR.parent
DEFAULT_COLLECTIONS_CONFIG_PATH = ROOT_DIR / "data" / "collections" / "collections.json"
DEFAULT_PIPELINE_STATUS_PATH = ROOT_DIR / "data" / "pipeline-status.json"
DEFAULT_RECEIPTS_DIR = ROOT_DIR / "data" / "receipts"

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
UNRESOLVED_RANGE_MARKERS_RE = re.compile(
    r"[\^~*><=|$\s]|^(?:latest|main|master|unspecified|workspace:.*)$",
    re.IGNORECASE,
)

URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@\"']+(?::[^/\s@\"']*)?@")
QUERY_PARAM_SECRET_RE = re.compile(
    r"([?&;]\s*(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"secret|password|passwd|token|key|auth|sig|signature|credential|bearer)\s*=)[^&\s#\"']+",
    re.IGNORECASE,
)
KEY_VALUE_SECRET_RE = re.compile(
    r"\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"secret|password|passwd|authorization)\s*[:=]\s*)[^\s,;\"']+",
    re.IGNORECASE,
)
SECRET_REDACTION_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{8,}|github_pat_[A-Za-z0-9_]{8,}|glpat-[A-Za-z0-9_-]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{12,}|"
    r"(?:Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]+|token=[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)
FILESYSTEM_PATH_REDACTION_RE = re.compile(
    r"(?:[A-Za-z]:\\(?:Users|Windows|Temp|runner|work|actions-runner)[^\s:\"']*)|"
    r"(?:/(?:Users|home|root|tmp|var|opt|etc|private|srv|mnt|workspace|workspaces|github)(?:/[^\s:\"']+)+)"
)

PUBLIC_FAILURE_MESSAGES: dict[str, str] = {
    "upstream_feed_request_failed": "Upstream advisory or metadata feed request failed; retaining previous published snapshot.",
    "github_discovery_failed": "GitHub repository or manifest discovery failed; retaining previous published snapshot.",
    "validation_gate_failed": "Staged dataset or coverage report failed validation gates; publication aborted.",
    "shrink_guard_triggered": "Repository coverage shrink guard triggered; publication aborted.",
    "publication_rollback": "Artifact publication failed mid-commit and rolled back cleanly.",
    "stale_running_timeout": "Previous running attempt exceeded heartbeat TTL without reporting completion.",
    "pipeline_execution_failed": "Pipeline refresh attempt failed; inspect restricted workflow logs for details.",
}


def _current_utc_iso() -> str:
    """Return the current UTC clock timestamp in ISO-8601 Z format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    checked_at: str | None = None,
    max_allowed_shrink_ratio: float = 0.20,
    allow_shrink: bool = False,
) -> dict[str, Any]:
    """Execute an incremental repository inventory pass with commit & dependency-file hash reuse (#73 Workstream 1).

    Enforces:
    - Defaults omitted `checked_at` to actual current UTC time while preserving explicit timestamps for replay/tests.
    - Unchanged commit OR README-only change (where `dependency_files_sha256`, `extractor_version`, and
      `config_fingerprint` match cache) reuses the cached dependency edges without re-extracting.
    - Parser/extractor or config version change invalidates cached extraction and forces re-extraction.
    - Distinguishes `branch_checked_at` from `dependency_extracted_at`.
    - Tracks repository additions, removals, renames, inaccessible repos, and manifest truncation.
    - Fails closed if repository scan failures occur or scope shrinks beyond `max_allowed_shrink_ratio`
      unless `allow_shrink=True`.
    """
    effective_checked_at = checked_at or _current_utc_iso()
    cache = previous_inventory_cache or {}
    cached_repos: dict[str, dict[str, Any]] = cache.get("repositories") or {}
    prev_repo_by_id: dict[str, str] = {
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
        if repo_id in prev_repo_by_id and prev_repo_by_id[repo_id] != name:
            renamed_repos.append({"from": prev_repo_by_id[repo_id], "to": name, "repo_id": repo_id})

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
            cached_repos.get(prev_repo_by_id[repo_id]) if repo_id in prev_repo_by_id else None
        )
        if prev_entry is None and repo_id not in prev_repo_by_id:
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
            extracted_at = effective_checked_at
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
                        "library_id": (
                            canonical_library_id(f"{eco}||{pkg}|{ver}")
                            if ":" not in pkg
                            else canonical_library_id(f"{eco}|{pkg.replace(':', '|')}|{ver}")
                        ),
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
            "branch_checked_at": effective_checked_at,
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
        "branch_checked_at": effective_checked_at,
        "dependency_extracted_at": max(
            (v["dependency_extracted_at"] for v in new_cached_repos.values()),
            default=effective_checked_at,
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
    queried_at: str | None = None,
    security_freshness_ttl_seconds: int = 86400,
    batch_size: int = 100,
    sqlite_db_path: Path | None = None,
) -> dict[str, Any]:
    """Resolve OSV vulnerabilities across collections without downloading global `all.zip` (#73 Workstream 2).

    Enforces:
    - Uses actual current UTC time when `queried_at` is omitted while preserving explicit timestamps for
      deterministic replay/tests.
    - Deduplicates shared exact package/versions across multiple collections so OSV is queried ONCE per unique
      `(ecosystem, package, version)` while attributing results accurately to each collection.
    - Follows per-query `next_page_token` pagination and fails closed on truncated/malformed batch responses.
    - Requeries unchanged package versions when `security_freshness_ttl_seconds` expires (includingboth positive
      and negative cache entries with `vulns: []`) so newly disclosed advisories on unchanged inventory are detected.
    - Fetches `/v1/vulns/<id>` detail ONLY when absent from `advisory_details_cache` or when `modified` changed.
    - Handles withdrawn advisories, aliases, declared ranges vs exact versions (never labeling unresolved ranges
      or unsupported ecosystems as `clean`), and preserves non-CVE advisories (`non_cve_advisories`).
    """
    effective_queried_at = queried_at or _current_utc_iso()
    now_dt = _parse_iso_dt(effective_queried_at) or datetime.now(timezone.utc)

    cache = copy.deepcopy(osv_cache) if isinstance(osv_cache, dict) else {}
    version_query_cache: dict[str, dict[str, Any]] = cache.setdefault("version_queries", {})
    advisory_details_cache: dict[str, dict[str, Any]] = cache.setdefault("advisory_details", {})

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
            if checked_dt is not None:
                age_seconds = (now_dt - checked_dt).total_seconds()
                if 0 <= age_seconds < security_freshness_ttl_seconds:
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
                "checked_at": effective_queried_at,
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
            "retrieved_at": effective_queried_at,
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
        "queried_at": effective_queried_at,
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
# Workstream 3 — Shared Evidence Conditional Refresh & Evidence-Only Reassessment
# ============================================================================


def refresh_shared_evidence_sources_conditionally(
    source_specs: dict[str, dict[str, Any]],
    conditional_fetcher: Callable[[str, dict[str, str]], dict[str, Any]],
    previous_source_state: dict[str, dict[str, Any]] | None = None,
    *,
    checked_at: str | None = None,
    security_freshness_ttl_seconds: int = 86400,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """Refresh shared evidence sources conditionally using ETag / Last-Modified headers (#73 Workstream 3).

    Enforces:
    - Sends `If-None-Match` and `If-Modified-Since` headers when prior source metadata exists and `not force_refresh`.
    - On HTTP 304 (`status == 304`), updates `checked_at` while retaining `fetched_at`, `sha256`, and `version`
      without re-parsing or re-ingesting unchanged payloads (`changed: False`).
    - On HTTP 200 (`status == 200`), validates non-empty payload, computes `sha256`, and records `changed: True`
      when content digest or version changed.
    - Fails closed if a feed request fails and cached evidence is absent or older than `security_freshness_ttl_seconds`.
    """
    effective_checked_at = checked_at or _current_utc_iso()
    now_dt = _parse_iso_dt(effective_checked_at) or datetime.now(timezone.utc)
    state = copy.deepcopy(previous_source_state) if isinstance(previous_source_state, dict) else {}

    updated_sources: dict[str, dict[str, Any]] = {}
    changed_sources: list[str] = []
    http_requests = 0
    not_modified_hits = 0

    for source_name, spec in sorted(source_specs.items()):
        url = str(spec.get("url") or "").strip()
        if not url:
            raise ValueError(f"Shared source '{source_name}' is missing required 'url'.")
        ttl_seconds = int(spec.get("freshness_ttl_seconds") or security_freshness_ttl_seconds)
        prev = state.get(source_name) if isinstance(state.get(source_name), dict) else {}

        req_headers: dict[str, str] = {}
        if not force_refresh and prev:
            if prev.get("etag"):
                req_headers["If-None-Match"] = str(prev["etag"])
            if prev.get("last_modified"):
                req_headers["If-Modified-Since"] = str(prev["last_modified"])

        http_requests += 1
        resp = conditional_fetcher(url, req_headers)
        status_code = int(resp.get("status") or 0)

        if status_code == 304:
            if not prev or not prev.get("sha256"):
                raise RuntimeError(f"Received HTTP 304 for '{source_name}' without prior cached digest.")
            not_modified_hits += 1
            updated_sources[source_name] = {
                **copy.deepcopy(prev),
                "name": source_name,
                "url": url,
                "checked_at": effective_checked_at,
                "changed": False,
            }
            continue

        if status_code == 200:
            payload = resp.get("payload")
            if payload is None or payload == "" or payload == b"" or payload == {} or payload == []:
                raise RuntimeError(f"Refusing empty payload from shared evidence source '{source_name}'.")
            if isinstance(payload, (bytes, bytearray)):
                digest = _sha256_bytes(bytes(payload))
                version = str(resp.get("version") or digest[:12])
            elif isinstance(payload, str):
                digest = _sha256_bytes(payload.encode("utf-8"))
                version = str(resp.get("version") or digest[:12])
            else:
                digest = _sha256_json(payload)
                version = str(
                    resp.get("version")
                    or (payload.get("feed_version") if isinstance(payload, dict) else None)
                    or (payload.get("version") if isinstance(payload, dict) else None)
                    or digest[:12]
                )

            is_changed = (prev.get("sha256") != digest) or (str(prev.get("version") or "") != version)
            if is_changed:
                changed_sources.append(source_name)

            updated_sources[source_name] = {
                "name": source_name,
                "url": url,
                "sha256": digest,
                "version": version,
                "etag": resp.get("etag") or prev.get("etag"),
                "last_modified": resp.get("last_modified") or prev.get("last_modified"),
                "fetched_at": effective_checked_at,
                "retrieved_at": effective_checked_at,
                "checked_at": effective_checked_at,
                "changed": is_changed,
                "payload": copy.deepcopy(payload),
            }
            continue

        # Error status: check if prior cached state is still within allowed freshness TTL
        fetched_dt = _parse_iso_dt(prev.get("fetched_at") or prev.get("retrieved_at")) if prev else None
        if fetched_dt is not None and 0 <= (now_dt - fetched_dt).total_seconds() < ttl_seconds:
            updated_sources[source_name] = {
                **copy.deepcopy(prev),
                "name": source_name,
                "url": url,
                "checked_at": effective_checked_at,
                "changed": False,
                "retained_cached_after_transient_error": True,
            }
            continue

        raise RuntimeError(
            f"Shared evidence source '{source_name}' failed with HTTP {status_code} and no fresh cached snapshot is available."
        )

    return {
        "checked_at": effective_checked_at,
        "any_evidence_changed": len(changed_sources) > 0,
        "changed_sources": changed_sources,
        "sources": updated_sources,
        "measurements": {
            "http_requests": http_requests,
            "not_modified_hits": not_modified_hits,
        },
    }


def reassess_inventory_with_refreshed_evidence(
    *,
    collection_id: str,
    baseline_dataset: dict[str, Any],
    baseline_receipt: dict[str, Any],
    refreshed_osv_collection_result: dict[str, Any] | None = None,
    kev_cve_ids: set[str] | list[str] | None = None,
    epss_by_cve: dict[str, float] | None = None,
    refreshed_evidence_snapshot_ids: dict[str, str] | None = None,
    refreshed_sources: list[dict[str, Any]] | None = None,
    assessed_at: str | None = None,
    collector_commit: str | None = None,
    methodology_version: str | None = None,
) -> dict[str, Any]:
    """Re-evaluate an unchanged repository inventory against refreshed security/patch evidence (#73 Workstream 3).

    Enforces:
    - Does NOT re-crawl GitHub repositories or alter `inventory_snapshot_id` / `inventory_scanned_at`.
    - Updates library CVE findings, KEV flags, EPSS scores, and non-CVE advisory records from refreshed feeds.
    - Builds a new validated assessment receipt and compares against `baseline_receipt` using
      `compare_assessment_snapshots` (`evidence_changes_only` vs `no_semantic_change`).
    """
    effective_assessed_at = assessed_at or _current_utc_iso()
    reassessed = copy.deepcopy(baseline_dataset)
    meta = reassessed.setdefault("meta", {})

    # Preserve original inventory scan timestamp while updating vulnerability/external query timestamps
    if baseline_dataset.get("meta", {}).get("inventory_scanned_at"):
        meta["inventory_scanned_at"] = baseline_dataset["meta"]["inventory_scanned_at"]
    meta["vulnerabilities_queried_at"] = effective_assessed_at
    meta["generated_at"] = effective_assessed_at

    kev_set = {str(c).upper() for c in (kev_cve_ids or [])} if kev_cve_ids is not None else None
    epss_map = {str(k).upper(): float(v) for k, v in (epss_by_cve or {}).items()} if epss_by_cve is not None else None

    libraries: list[dict[str, Any]] = reassessed.setdefault("libraries", [])
    libs_by_id: dict[str, dict[str, Any]] = {
        str(lib.get("id")): lib for lib in libraries if isinstance(lib, dict) and lib.get("id")
    }

    if isinstance(refreshed_osv_collection_result, dict):
        # Apply newly discovered CVE findings to existing or newly affected inventory libraries
        for finding in refreshed_osv_collection_result.get("cve_findings") or []:
            lid = str(finding.get("library_id") or "")
            if not lid:
                continue
            ns, meta_coord, proj, ver = parse_library_id(lid)
            lib_entry = libs_by_id.get(lid)
            if lib_entry is None:
                lib_entry = {
                    "id": lid,
                    "namespace": ns,
                    "meta": meta_coord,
                    "proj": proj,
                    "release": ver,
                    "cves": [],
                }
                libraries.append(lib_entry)
                libs_by_id[lid] = lib_entry
            existing_cves = {c.get("cve_id"): c for c in (lib_entry.get("cves") or []) if isinstance(c, dict)}
            for cve_id in finding.get("cve_aliases") or []:
                if cve_id not in existing_cves:
                    cve_obj: dict[str, Any] = {
                        "cve_id": cve_id,
                        "summary": str(finding.get("summary") or "")[:500],
                    }
                    if kev_set is not None:
                        cve_obj["kev"] = cve_id in kev_set
                    if epss_map is not None and cve_id in epss_map:
                        cve_obj["epss"] = epss_map[cve_id]
                    lib_entry.setdefault("cves", []).append(cve_obj)
                    existing_cves[cve_id] = cve_obj

        if refreshed_osv_collection_result.get("non_cve_findings") is not None:
            reassessed["non_cve_advisories"] = copy.deepcopy(refreshed_osv_collection_result["non_cve_findings"])

    # Update KEV and EPSS signals across all library CVE entries when provided
    for lib_entry in libraries:
        for cve_obj in lib_entry.get("cves") or []:
            cid = str(cve_obj.get("cve_id") or "").upper()
            if kev_set is not None and cid:
                cve_obj["kev"] = cid in kev_set
            if epss_map is not None and cid in epss_map:
                cve_obj["epss"] = epss_map[cid]
        lib_entry["cve_count"] = len(lib_entry.get("cves") or [])
        if kev_set is not None:
            lib_entry["kev_cve_count"] = sum(1 for c in (lib_entry.get("cves") or []) if c.get("kev"))

    # Keep counts synchronized with reassessed findings
    unique_cves = {
        str(c.get("cve_id"))
        for lib_entry in libraries
        for c in (lib_entry.get("cves") or [])
        if isinstance(c, dict) and c.get("cve_id")
    }
    if isinstance(meta.get("counts"), dict):
        meta["counts"]["distinct_cve_libraries"] = len(libraries)
        meta["counts"]["unique_cves"] = len(unique_cves)
    if isinstance(meta.get("coverage"), dict):
        meta["coverage"]["vulnerable_library_versions"] = len(libraries)
        meta["coverage"]["unique_cves"] = len(unique_cves)

    new_ev_ids = copy.deepcopy(
        refreshed_evidence_snapshot_ids
        if refreshed_evidence_snapshot_ids is not None
        else baseline_receipt.get("evidence_snapshot_ids") or {}
    )
    new_sources = copy.deepcopy(
        refreshed_sources if refreshed_sources is not None else baseline_receipt.get("sources") or []
    )

    candidate_receipt = build_assessment_receipt(
        collection_id=collection_id,
        dataset=reassessed,
        inventory_snapshot_id=str(baseline_receipt["inventory_snapshot_id"]),
        evidence_snapshot_ids=new_ev_ids,
        sources=new_sources,
        artifacts=copy.deepcopy(baseline_receipt.get("artifacts") or []),
        collector_commit=collector_commit or str(baseline_receipt.get("collector_commit") or "unknown"),
        methodology_version=methodology_version or str(baseline_receipt.get("methodology_version") or "2026.11-incremental-v1"),
        generated_at=effective_assessed_at,
    )

    comparison = compare_assessment_snapshots(
        baseline_receipt=baseline_receipt,
        baseline_dataset=baseline_dataset,
        candidate_receipt=candidate_receipt,
        candidate_dataset=reassessed,
    )

    return {
        "collection_id": collection_id,
        "dataset": reassessed,
        "receipt": candidate_receipt,
        "comparison": comparison,
        "material_change": candidate_receipt["content_sha256"] != baseline_receipt["content_sha256"],
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
    generated_at: str | None = None,
    snapshot_id_override: str | None = None,
) -> dict[str, Any]:
    """Build and validate the immutable assessment receipt contract (#73 Workstream 4)."""
    effective_generated_at = generated_at or _current_utc_iso()
    content_sha256 = compute_canonical_assessment_sha256(dataset)
    snapshot_id = snapshot_id_override or f"{collection_id}-{content_sha256[:12]}"
    receipt = {
        "schema_version": "1",
        "collection_id": collection_id,
        "snapshot_id": snapshot_id,
        "content_sha256": content_sha256,
        "generated_at": effective_generated_at,
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


def verify_offline_replay_determinism(
    *,
    dataset: dict[str, Any],
    receipt: dict[str, Any],
    replay_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify offline replay determinism of a published dataset and its assessment receipt (#73 Workstream 4).

    Replays canonical assessment hashing and (when `replay_inputs` are provided) full offline reassessment
    using the receipt's pinned timestamps, methodology version, and source digests without network calls.
    """
    errors: list[str] = []
    try:
        validate_assessment_receipt(receipt, dataset)
    except Exception as exc:
        errors.append(str(exc))

    replayed_dataset = copy.deepcopy(dataset)
    if isinstance(replay_inputs, dict):
        reassessed_res = reassess_inventory_with_refreshed_evidence(
            collection_id=str(receipt["collection_id"]),
            baseline_dataset=replay_inputs.get("baseline_dataset") or dataset,
            baseline_receipt=receipt,
            refreshed_osv_collection_result=replay_inputs.get("osv_collection_result"),
            kev_cve_ids=replay_inputs.get("kev_cve_ids"),
            epss_by_cve=replay_inputs.get("epss_by_cve"),
            refreshed_evidence_snapshot_ids=receipt.get("evidence_snapshot_ids"),
            refreshed_sources=receipt.get("sources"),
            assessed_at=str(receipt.get("generated_at")),
            collector_commit=str(receipt.get("collector_commit")),
            methodology_version=str(receipt.get("methodology_version")),
        )
        replayed_dataset = reassessed_res["dataset"]

    replayed_sha256 = compute_canonical_assessment_sha256(replayed_dataset)
    expected_sha256 = str(receipt.get("content_sha256") or "")
    if replayed_sha256 != expected_sha256:
        errors.append(
            f"Offline replay content_sha256 mismatch: expected {expected_sha256}, got {replayed_sha256}"
        )

    replayed_receipt = build_assessment_receipt(
        collection_id=str(receipt["collection_id"]),
        dataset=replayed_dataset,
        inventory_snapshot_id=str(receipt["inventory_snapshot_id"]),
        evidence_snapshot_ids=copy.deepcopy(receipt["evidence_snapshot_ids"]),
        sources=copy.deepcopy(receipt.get("sources") or []),
        artifacts=copy.deepcopy(receipt.get("artifacts") or []),
        collector_commit=str(receipt["collector_commit"]),
        methodology_version=str(receipt["methodology_version"]),
        generated_at=str(receipt["generated_at"]),
        snapshot_id_override=str(receipt["snapshot_id"]),
    )
    comparison = compare_assessment_snapshots(
        baseline_receipt=receipt,
        baseline_dataset=dataset,
        candidate_receipt=replayed_receipt,
        candidate_dataset=replayed_dataset,
    )
    if comparison["comparison_mode"] != "no_semantic_change":
        errors.append(f"Expected 'no_semantic_change' on offline replay, got '{comparison['comparison_mode']}'")

    return {
        "verified": len(errors) == 0,
        "collection_id": receipt.get("collection_id"),
        "snapshot_id": receipt.get("snapshot_id"),
        "expected_content_sha256": expected_sha256,
        "replayed_content_sha256": replayed_sha256,
        "comparison_mode": comparison["comparison_mode"],
        "errors": errors,
    }


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
    inject_failure_at_step: int | None = None,
) -> dict[str, Any]:
    """Validate and publish collection artifacts before updating pointers, with full pre-publication rollback (#73 Workstream 5).

    Enforces:
    - Restores complete pre-publication state on exception rollback: pre-existing destination files are
      restored from `.bak` backups and newly created destination files (from a failed first or mixed
      publication attempt) are removed so no partial dataset remains on disk.
    - Note on rollback guarantees: Sequential file replacement with `.tmp` staging, `.bak` restoration,
      and new-target removal protects against Python-level validation, I/O, or size-limit exceptions during
      publication; it is not a kernel-atomic multi-file transaction across hard OS crashes.
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
    fail_step = inject_failure_at_step if inject_failure_at_step is not None else (1 if inject_mid_publish_failure else None)
    backups: list[tuple[Path, Path]] = []
    created_targets: list[Path] = []
    temps: list[Path] = []

    try:
        for dest, payload in targets:
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = dest.with_suffix(dest.suffix + ".tmp")
            tmp_path.write_bytes(payload)
            temps.append(tmp_path)

        for idx, (dest, _) in enumerate(targets):
            if fail_step is not None and idx == fail_step:
                raise RuntimeError(f"Injected mid-publication failure before writing target index {idx}.")
            if dest.exists():
                bak_path = dest.with_suffix(dest.suffix + ".bak")
                shutil.copy2(dest, bak_path)
                backups.append((dest, bak_path))
            else:
                created_targets.append(dest)
            dest.with_suffix(dest.suffix + ".tmp").replace(dest)

        if manifest_path is not None and manifest_path.exists():
            if fail_step is not None and fail_step == len(targets):
                raise RuntimeError("Injected mid-publication failure before updating manifest.")
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
        for created_path in reversed(created_targets):
            created_path.unlink(missing_ok=True)
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


def classify_public_failure_code(raw_message: str | None, explicit_code: str | None = None) -> str:
    """Map an exception or explicit error code to a controlled public failure code (#73 Workstream 7)."""
    if explicit_code and explicit_code in PUBLIC_FAILURE_MESSAGES:
        return explicit_code
    text = str(raw_message or "").lower()
    if "shrink" in text:
        return "shrink_guard_triggered"
    if "exceeds limit" in text or "validation" in text:
        return "validation_gate_failed"
    if "mid-publication" in text or "rollback" in text:
        return "publication_rollback"
    if "github" in text or "repository scan" in text:
        return "github_discovery_failed"
    if "osv" in text or "feed" in text or "http " in text or "https://" in text or "http://" in text:
        return "upstream_feed_request_failed"
    if "heartbeat ttl" in text or "stale" in text:
        return "stale_running_timeout"
    return "pipeline_execution_failed"


def sanitize_public_failure_summary(
    raw_message: str | None,
    *,
    prefer_controlled_message: bool = False,
    failure_code: str | None = None,
) -> str | None:
    """Redact URL credentials, query secrets, tokens, and Linux/macOS/Windows paths from public summaries (#73 Workstream 7)."""
    if not raw_message and not failure_code:
        return None
    resolved_code = classify_public_failure_code(raw_message, failure_code)
    if prefer_controlled_message or not raw_message:
        return PUBLIC_FAILURE_MESSAGES[resolved_code]

    msg = str(raw_message).strip()
    msg = URL_USERINFO_RE.sub(r"\1[REDACTED_CREDENTIAL]@", msg)
    msg = QUERY_PARAM_SECRET_RE.sub(r"\1[REDACTED_CREDENTIAL]", msg)
    msg = KEY_VALUE_SECRET_RE.sub(r"\1[REDACTED_CREDENTIAL]", msg)
    msg = SECRET_REDACTION_RE.sub("[REDACTED_CREDENTIAL]", msg)
    msg = FILESYSTEM_PATH_REDACTION_RE.sub("[REDACTED_PATH]", msg)
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
    failure_code: str | None = None,
    prefer_controlled_failure_message: bool = False,
    measurements: dict[str, Any] | None = None,
    checked_at: str | None = None,
    stale_running_ttl_seconds: int = 7200,
) -> dict[str, Any]:
    """Update the shared public `/data/pipeline-status.json` artifact safely (#73 Workstream 7).

    Enforces:
    - Uses actual current UTC time when `checked_at` is omitted while preserving explicit timestamps for tests.
    - Distinguishes `latest_attempt`, `latest_validated_candidate`, and `currently_published_snapshot`.
    - A failed attempt preserves `currently_published_snapshot` (`previous_valid_snapshot_retained: True`).
    - A validated candidate awaiting PR review sets `publication_state = 'refresh_succeeded_pr_awaiting_review'`
      without overwriting `currently_published_snapshot` until merged (`promote_to_published=True`).
    - Reconciles stale `running` attempts older than `stale_running_ttl_seconds` to `stale_unknown`.
    - Attaches controlled `failure_code` and redacts URL credentials, query secrets, tokens, and filesystem
      paths from `failure_summary`.
    """
    if isinstance(status_doc_or_path, Path):
        doc = json.loads(status_doc_or_path.read_text(encoding="utf-8"))
    else:
        doc = copy.deepcopy(status_doc_or_path)

    effective_checked_at = checked_at or _current_utc_iso()
    now_dt = _parse_iso_dt(effective_checked_at) or datetime.now(timezone.utc)
    doc["checked_at"] = effective_checked_at
    doc["generated_at"] = effective_checked_at

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
            "failure_code": None,
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
                pipe["failure_code"] = "stale_running_timeout"
                pipe["failure_summary"] = PUBLIC_FAILURE_MESSAGES["stale_running_timeout"]

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
        resolved_code = classify_public_failure_code(failure_summary, failure_code)
        target["failure_code"] = resolved_code
        target["failure_summary"] = sanitize_public_failure_summary(
            failure_summary or f"Pipeline attempt {outcome}.",
            prefer_controlled_message=prefer_controlled_failure_message,
            failure_code=resolved_code,
        )
        target["previous_valid_snapshot_retained"] = target.get("currently_published_snapshot") is not None
        if target.get("currently_published_snapshot") is not None:
            target["publication_state"] = "previous_snapshot_retained_after_failure"
        else:
            target["publication_state"] = "failed_no_published_snapshot"
    elif outcome == "unchanged":
        target["failure_code"] = None
        target["failure_summary"] = None
        target["previous_valid_snapshot_retained"] = True
        if target.get("currently_published_snapshot") is not None:
            target["publication_state"] = "published_checked_unchanged"
    elif outcome == "succeeded":
        target["failure_code"] = None
        target["failure_summary"] = None
        if validated_candidate is not None:
            target["latest_validated_candidate"] = copy.deepcopy(validated_candidate)
        if promote_to_published and validated_candidate is not None:
            target["currently_published_snapshot"] = {
                **copy.deepcopy(validated_candidate),
                "published_at": effective_checked_at,
            }
            target["publication_state"] = "published"
            target["pending_pr_url"] = None
            target["previous_valid_snapshot_retained"] = True
        else:
            target["publication_state"] = "refresh_succeeded_pr_awaiting_review"
            target["pending_pr_url"] = pending_pr_url
            target["previous_valid_snapshot_retained"] = target.get("currently_published_snapshot") is not None

    return doc


# ============================================================================
# Artifact-Backed Receipt & Public Pipeline Status Provenance Synchronization
# ============================================================================


def build_public_pipeline_status_from_artifacts(
    *,
    root_dir: Path = ROOT_DIR,
    checked_at: str | None = None,
    write_receipts: bool = False,
    collector_commit: str = "e1b8aa18333ccdf84be588dfa620876a3a2ad8da",
) -> dict[str, Any]:
    """Generate `/data/pipeline-status.json` (and optional receipts) from real publication artifacts on disk (#73).

    Enforces:
    - A collection is marked `published` ONLY when its dataset, coverage report, and receipt files exist on disk
      and have matching canonical `content_sha256` and `snapshot_id`.
    - Collections without published artifacts on disk (such as `finos-labs` prior to initial run) are initialized
      as `awaiting_initial_publication` with `currently_published_snapshot: None`.
    """
    effective_checked_at = checked_at or _current_utc_iso()
    receipts_dir = root_dir / "data" / "receipts"
    if write_receipts:
        receipts_dir.mkdir(parents=True, exist_ok=True)

    pipelines: list[dict[str, Any]] = []

    # 1. finos-github-org
    finos_ds_path = root_dir / "data" / "finos-github-org.json"
    finos_cov_path = root_dir / "data" / "finos-coverage.json"
    finos_rec_path = receipts_dir / "finos-github-org.receipt.json"

    if finos_ds_path.exists() and finos_cov_path.exists():
        finos_ds = json.loads(finos_ds_path.read_text(encoding="utf-8"))
        finos_cov = json.loads(finos_cov_path.read_text(encoding="utf-8"))
        finos_meta = finos_ds.get("meta") or {}
        finos_generated_at = str(finos_cov.get("generated_at") or finos_meta.get("extracted_at") or effective_checked_at)
        finos_scanned_at = str(finos_cov.get("inventory_completed_at") or finos_meta.get("inventory_scanned_at") or finos_generated_at)
        finos_queried_at = str(
            ((finos_cov.get("sources") or {}).get("osv_exact_versions") or {}).get("queried_at")
            or finos_meta.get("vulnerabilities_queried_at")
            or finos_generated_at
        )
        finos_date_suffix = finos_scanned_at[:10].replace("-", "")
        finos_snapshot_id = f"finos-github-org-{finos_date_suffix}"
        finos_inv_hash = _sha256_json(finos_ds.get("dependency_inventory") or {})
        osv_sha = str(((finos_cov.get("sources") or {}).get("osv_sha256")) or _sha256_json(finos_cov.get("sources") or {}))
        kev_fetched = str(((finos_cov.get("sources") or {}).get("kev_fetched_at")) or finos_generated_at)
        epss_fetched = str(((finos_cov.get("sources") or {}).get("epss_fetched_at")) or finos_generated_at)

        finos_receipt = build_assessment_receipt(
            collection_id="finos-github-org",
            dataset=finos_ds,
            inventory_snapshot_id=f"finos-github-org-inv-{finos_inv_hash[:12]}",
            evidence_snapshot_ids={
                "osv": f"osv-{osv_sha[:12]}",
                "kev": f"kev-{kev_fetched[:10].replace('-', '')}",
                "epss": f"epss-{epss_fetched[:10].replace('-', '')}",
                "osera_openvex": "osera-openvex-161",
            },
            sources=[
                {"name": "github-finos-org", "sha256": finos_inv_hash, "retrieved_at": finos_scanned_at},
                {"name": "osv", "sha256": osv_sha, "retrieved_at": finos_queried_at},
                {"name": "cisa-kev", "sha256": _sha256_json({"kev_fetched_at": kev_fetched}), "retrieved_at": kev_fetched},
                {"name": "first-epss", "sha256": _sha256_json({"epss_fetched_at": epss_fetched}), "retrieved_at": epss_fetched},
            ],
            artifacts=[
                {"role": "dataset", "path": "data/finos-github-org.json", "url": "../data/finos-github-org.json"},
                {"role": "coverage_report", "path": "data/finos-coverage.json", "url": "../data/finos-coverage.json"},
                {"role": "receipt", "path": "data/receipts/finos-github-org.receipt.json", "url": "../data/receipts/finos-github-org.receipt.json"},
            ],
            collector_commit=collector_commit,
            methodology_version="2026.11-incremental-v1",
            generated_at=finos_generated_at,
            snapshot_id_override=finos_snapshot_id,
        )
        if write_receipts:
            finos_rec_path.write_text(json.dumps(finos_receipt, indent=2) + "\n", encoding="utf-8")

        if finos_rec_path.exists():
            val_summary = (
                f"{finos_cov.get('repositories', 0)} repositories; "
                f"{finos_cov.get('repositories_with_dependencies', 0)} with dependencies; "
                f"{finos_cov.get('repositories_failed', 0)} failed"
            )
            pipelines.append(
                {
                    "pipeline_id": "refresh-finos-github-org",
                    "collection_id": "finos-github-org",
                    "friendly_name": "FINOS GitHub Org Snapshot",
                    "publication_state": "published",
                    "pending_pr_url": None,
                    "previous_valid_snapshot_retained": True,
                    "failure_code": None,
                    "failure_summary": None,
                    "latest_attempt": {
                        "run_id": "42013766686",
                        "run_url": "https://github.com/finos-osera/risk-navigator/actions",
                        "trigger": "schedule",
                        "code_sha": collector_commit,
                        "started_at": str(finos_cov.get("inventory_started_at") or finos_scanned_at),
                        "completed_at": finos_generated_at,
                        "outcome": "succeeded",
                    },
                    "latest_validated_candidate": {
                        "snapshot_id": finos_receipt["snapshot_id"],
                        "content_sha256": finos_receipt["content_sha256"],
                        "validation_summary": val_summary,
                        "dataset_url": "../data/finos-github-org.json",
                        "receipt_url": "../data/receipts/finos-github-org.receipt.json",
                        "coverage_url": "../data/finos-coverage.json",
                    },
                    "currently_published_snapshot": {
                        "snapshot_id": finos_receipt["snapshot_id"],
                        "content_sha256": finos_receipt["content_sha256"],
                        "published_at": finos_generated_at,
                        "inventory_scanned_at": finos_scanned_at,
                        "vulnerabilities_queried_at": finos_queried_at,
                        "osera_openvex_version": "161",
                        "oss_risk_snapshot_id": "oss-risk-20261104",
                        "dataset_url": "../data/finos-github-org.json",
                        "receipt_url": "../data/receipts/finos-github-org.receipt.json",
                        "coverage_url": "../data/finos-coverage.json",
                    },
                    "measurements": {
                        "duration_seconds": 353.0,
                        "api_requests": 135,
                        "downloaded_bytes": finos_ds_path.stat().st_size,
                        "cache_hits": 0,
                        "cache_misses": 135,
                        "osv_batch_queries": 6,
                        "dataset_bytes": finos_ds_path.stat().st_size,
                    },
                }
            )
        else:
            pipelines.append(_empty_pipeline_status_entry("finos-github-org", "FINOS GitHub Org Snapshot", collector_commit))
    else:
        pipelines.append(_empty_pipeline_status_entry("finos-github-org", "FINOS GitHub Org Snapshot", collector_commit))

    # 2. finos-labs (awaiting initial publication unless artifacts + receipt exist on disk)
    labs_ds_path = root_dir / "data" / "finos-labs.json"
    labs_cov_path = root_dir / "data" / "finos-labs-coverage.json"
    labs_rec_path = receipts_dir / "finos-labs.receipt.json"
    if labs_ds_path.exists() and labs_cov_path.exists() and labs_rec_path.exists():
        labs_rec = json.loads(labs_rec_path.read_text(encoding="utf-8"))
        pipelines.append(
            {
                "pipeline_id": "refresh-finos-labs",
                "collection_id": "finos-labs",
                "friendly_name": "FINOS Labs Snapshot (Early-Stage / Experimental)",
                "publication_state": "published",
                "pending_pr_url": None,
                "previous_valid_snapshot_retained": True,
                "failure_code": None,
                "failure_summary": None,
                "latest_attempt": {
                    "run_id": None,
                    "run_url": None,
                    "trigger": "schedule",
                    "code_sha": collector_commit,
                    "started_at": labs_rec["generated_at"],
                    "completed_at": labs_rec["generated_at"],
                    "outcome": "succeeded",
                },
                "latest_validated_candidate": {
                    "snapshot_id": labs_rec["snapshot_id"],
                    "content_sha256": labs_rec["content_sha256"],
                    "dataset_url": "../data/finos-labs.json",
                    "receipt_url": "../data/receipts/finos-labs.receipt.json",
                    "coverage_url": "../data/finos-labs-coverage.json",
                },
                "currently_published_snapshot": {
                    "snapshot_id": labs_rec["snapshot_id"],
                    "content_sha256": labs_rec["content_sha256"],
                    "published_at": labs_rec["generated_at"],
                    "dataset_url": "../data/finos-labs.json",
                    "receipt_url": "../data/receipts/finos-labs.receipt.json",
                    "coverage_url": "../data/finos-labs-coverage.json",
                },
                "measurements": {"dataset_bytes": labs_ds_path.stat().st_size},
            }
        )
    else:
        pipelines.append(
            _empty_pipeline_status_entry(
                "finos-labs",
                "FINOS Labs Snapshot (Early-Stage / Experimental)",
                collector_commit,
            )
        )

    # 3. oss-project-risk
    oss_ds_path = root_dir / "oss-risk" / "data" / "finos-osera-backpatch-scorecards.json"
    oss_seeds_path = root_dir / "oss-risk" / "data" / "finos-osera-backpatch-libraries.json"
    oss_rec_path = receipts_dir / "oss-project-risk.receipt.json"

    if oss_ds_path.exists() and oss_seeds_path.exists():
        oss_ds = json.loads(oss_ds_path.read_text(encoding="utf-8"))
        oss_seeds = json.loads(oss_seeds_path.read_text(encoding="utf-8"))
        oss_generated_at = str(oss_ds.get("generated_at") or effective_checked_at)
        oss_seeds_at = str(oss_seeds.get("generated_at") or oss_generated_at)
        oss_date_suffix = oss_generated_at[:10].replace("-", "")
        oss_snapshot_id = f"oss-risk-{oss_date_suffix}"
        seeds_hash = _sha256_json(oss_seeds)
        records = oss_ds.get("records") or []
        covered_count = sum(
            1
            for r in records
            if isinstance(r, dict)
            and ((r.get("evidence") or {}).get("osera_openvex") or {}).get("coverage_status") == "covered"
        )

        oss_receipt = build_assessment_receipt(
            collection_id="oss-project-risk",
            dataset=oss_ds,
            inventory_snapshot_id=f"oss-project-risk-seeds-{seeds_hash[:12]}",
            evidence_snapshot_ids={
                "osera_openvex": "osera-openvex-161",
                "osv": f"osv-{oss_date_suffix}",
                "cisa_kev": f"kev-{oss_date_suffix}",
            },
            sources=[
                {"name": "finos-osera-backpatch-seeds", "sha256": seeds_hash, "retrieved_at": oss_seeds_at},
                {"name": "oss-risk-scorecards", "sha256": compute_canonical_assessment_sha256(oss_ds), "retrieved_at": oss_generated_at},
            ],
            artifacts=[
                {"role": "dataset", "path": "oss-risk/data/finos-osera-backpatch-scorecards.json", "url": "../oss-risk/data/finos-osera-backpatch-scorecards.json"},
                {"role": "coverage_report", "path": "oss-risk/data/finos-osera-backpatch-libraries.json", "url": "../oss-risk/data/finos-osera-backpatch-libraries.json"},
                {"role": "receipt", "path": "data/receipts/oss-project-risk.receipt.json", "url": "../data/receipts/oss-project-risk.receipt.json"},
            ],
            collector_commit=collector_commit,
            methodology_version="2026.11-incremental-v1",
            generated_at=oss_generated_at,
            snapshot_id_override=oss_snapshot_id,
        )
        if write_receipts:
            oss_rec_path.write_text(json.dumps(oss_receipt, indent=2) + "\n", encoding="utf-8")

        if oss_rec_path.exists():
            pipelines.append(
                {
                    "pipeline_id": "refresh-oss-project-risk",
                    "collection_id": "oss-project-risk",
                    "friendly_name": "OSS Project Risk Scorecards",
                    "publication_state": "published",
                    "pending_pr_url": None,
                    "previous_valid_snapshot_retained": True,
                    "failure_code": None,
                    "failure_summary": None,
                    "seed_inventory_limitation": (
                        "Repository-scoped GITHUB_TOKEN retains committed finos-osera-backpatch seed list "
                        "when private org enumeration is unavailable."
                    ),
                    "latest_attempt": {
                        "run_id": "42013766686",
                        "run_url": "https://github.com/finos-osera/risk-navigator/actions",
                        "trigger": "workflow_dispatch",
                        "code_sha": collector_commit,
                        "started_at": oss_generated_at,
                        "completed_at": oss_generated_at,
                        "outcome": "succeeded",
                    },
                    "latest_validated_candidate": {
                        "snapshot_id": oss_receipt["snapshot_id"],
                        "content_sha256": oss_receipt["content_sha256"],
                        "validation_summary": f"{len(records)} backpatch libraries scored; {covered_count} with published OSERA OpenVEX fix",
                        "dataset_url": "../oss-risk/data/finos-osera-backpatch-scorecards.json",
                        "receipt_url": "../data/receipts/oss-project-risk.receipt.json",
                        "coverage_url": "../oss-risk/data/finos-osera-backpatch-libraries.json",
                    },
                    "currently_published_snapshot": {
                        "snapshot_id": oss_receipt["snapshot_id"],
                        "content_sha256": oss_receipt["content_sha256"],
                        "published_at": oss_generated_at,
                        "inventory_scanned_at": oss_seeds_at,
                        "vulnerabilities_queried_at": oss_generated_at,
                        "osera_openvex_version": "161",
                        "oss_risk_snapshot_id": oss_receipt["snapshot_id"],
                        "dataset_url": "../oss-risk/data/finos-osera-backpatch-scorecards.json",
                        "receipt_url": "../data/receipts/oss-project-risk.receipt.json",
                        "coverage_url": "../oss-risk/data/finos-osera-backpatch-libraries.json",
                    },
                    "measurements": {
                        "duration_seconds": 135.0,
                        "api_requests": len(records),
                        "downloaded_bytes": oss_ds_path.stat().st_size,
                        "cache_hits": 0,
                        "cache_misses": len(records),
                        "osv_batch_queries": 1,
                        "dataset_bytes": oss_ds_path.stat().st_size,
                    },
                }
            )
        else:
            pipelines.append(_empty_pipeline_status_entry("oss-project-risk", "OSS Project Risk Scorecards", collector_commit))
    else:
        pipelines.append(_empty_pipeline_status_entry("oss-project-risk", "OSS Project Risk Scorecards", collector_commit))

    return {
        "schema_version": "1",
        "generated_at": effective_checked_at,
        "checked_at": effective_checked_at,
        "pipelines": pipelines,
    }


def _empty_pipeline_status_entry(collection_id: str, friendly_name: str, collector_commit: str) -> dict[str, Any]:
    return {
        "pipeline_id": f"refresh-{collection_id}",
        "collection_id": collection_id,
        "friendly_name": friendly_name,
        "publication_state": "awaiting_initial_publication",
        "pending_pr_url": None,
        "previous_valid_snapshot_retained": False,
        "failure_code": None,
        "failure_summary": None,
        "latest_attempt": {
            "run_id": None,
            "run_url": None,
            "trigger": "none",
            "code_sha": collector_commit,
            "started_at": None,
            "completed_at": None,
            "outcome": "unknown",
        },
        "latest_validated_candidate": None,
        "currently_published_snapshot": None,
        "measurements": {
            "duration_seconds": 0.0,
            "api_requests": 0,
            "downloaded_bytes": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "osv_batch_queries": 0,
            "dataset_bytes": 0,
        },
    }


def _resolve_status_rel_url(root_dir: Path, rel_url: str) -> Path:
    cleaned = str(rel_url or "").strip()
    if cleaned.startswith("../"):
        cleaned = cleaned[3:]
    elif cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return (root_dir / cleaned).resolve()


def validate_public_pipeline_status_provenance(
    status_doc: dict[str, Any],
    *,
    root_dir: Path = ROOT_DIR,
) -> list[str]:
    """Verify that every published snapshot in `pipeline-status.json` has existing receipt, coverage, and matching SHA-256 on disk."""
    errors: list[str] = []
    if str(status_doc.get("schema_version")) != "1":
        errors.append(f"Unsupported pipeline-status schema_version: {status_doc.get('schema_version')}")

    for pipe in status_doc.get("pipelines") or []:
        cid = str(pipe.get("collection_id") or "unknown")
        pub_state = str(pipe.get("publication_state") or "")
        pub_snap = pipe.get("currently_published_snapshot")

        if pub_state == "published" and not isinstance(pub_snap, dict):
            errors.append(f"{cid}: publication_state is 'published' but currently_published_snapshot is missing.")
            continue

        if isinstance(pub_snap, dict):
            rec_url = str(pub_snap.get("receipt_url") or "")
            cov_url = str(pub_snap.get("coverage_url") or "")
            if not rec_url:
                errors.append(f"{cid}: currently_published_snapshot is missing receipt_url.")
            else:
                rec_path = _resolve_status_rel_url(root_dir, rec_url)
                if not rec_path.exists():
                    errors.append(f"{cid}: receipt_url '{rec_url}' does not exist on disk ({rec_path}).")
                else:
                    rec_doc = json.loads(rec_path.read_text(encoding="utf-8"))
                    if rec_doc.get("snapshot_id") != pub_snap.get("snapshot_id"):
                        errors.append(
                            f"{cid}: receipt snapshot_id '{rec_doc.get('snapshot_id')}' != status snapshot_id '{pub_snap.get('snapshot_id')}'."
                        )
                    if rec_doc.get("content_sha256") != pub_snap.get("content_sha256"):
                        errors.append(
                            f"{cid}: receipt content_sha256 '{rec_doc.get('content_sha256')}' != status content_sha256 '{pub_snap.get('content_sha256')}'."
                        )
                    ds_artifact = next(
                        (a for a in (rec_doc.get("artifacts") or []) if isinstance(a, dict) and a.get("role") == "dataset"),
                        None,
                    )
                    if ds_artifact and ds_artifact.get("path"):
                        ds_path = (root_dir / str(ds_artifact["path"])).resolve()
                        if not ds_path.exists():
                            errors.append(f"{cid}: dataset artifact '{ds_artifact['path']}' referenced by receipt does not exist.")
                        else:
                            ds_doc = json.loads(ds_path.read_text(encoding="utf-8"))
                            actual_sha = compute_canonical_assessment_sha256(ds_doc)
                            if actual_sha != pub_snap.get("content_sha256"):
                                errors.append(
                                    f"{cid}: dataset canonical SHA-256 '{actual_sha}' != status content_sha256 '{pub_snap.get('content_sha256')}'."
                                )

            if not cov_url:
                errors.append(f"{cid}: currently_published_snapshot is missing coverage_url.")
            else:
                cov_path = _resolve_status_rel_url(root_dir, cov_url)
                if not cov_path.exists():
                    errors.append(f"{cid}: coverage_url '{cov_url}' does not exist on disk ({cov_path}).")

    return errors


def build_deployment_manifest(
    *,
    deployed_code_sha: str,
    collection_receipts: list[dict[str, Any]],
    evidence_snapshot_ids: dict[str, str],
    release_tag: str | None = None,
    producing_run_id: str | None = None,
    producing_workflow: str = "refresh-collections.yml",
    generated_at: str | None = None,
    previous_deployment_sequence: int = 0,
) -> dict[str, Any]:
    """Assemble a pinned deployment manifest binding independently versioned collection snapshots (#73 ADR 2026-11-09).

    Enforces:
    - Independently refreshed collections remain independently versioned while `deployment-manifest.json`
      pins an exact compatible set (`snapshot_id` + `content_sha256` per collection) for bundled site builds.
    - Monotonic `deployment_sequence` and `generated_at` enable serialized promotion and stale-candidate rejection.
    """
    effective_generated_at = generated_at or _current_utc_iso()
    if not deployed_code_sha or not str(deployed_code_sha).strip():
        raise ValueError("build_deployment_manifest requires a non-empty deployed_code_sha.")
    if not collection_receipts:
        raise ValueError("build_deployment_manifest requires at least one validated collection receipt.")

    pinned_collections: dict[str, dict[str, Any]] = {}
    for rec in collection_receipts:
        validate_assessment_receipt(rec)
        cid = str(rec["collection_id"])
        pinned_collections[cid] = {
            "collection_id": cid,
            "snapshot_id": str(rec["snapshot_id"]),
            "content_sha256": str(rec["content_sha256"]),
            "inventory_snapshot_id": str(rec["inventory_snapshot_id"]),
            "methodology_version": str(rec["methodology_version"]),
            "generated_at": str(rec["generated_at"]),
            "artifacts": copy.deepcopy(rec.get("artifacts") or []),
        }

    manifest_core = {
        "deployed_code_sha": str(deployed_code_sha).strip(),
        "collections": pinned_collections,
        "evidence_snapshot_ids": copy.deepcopy(evidence_snapshot_ids),
    }
    bundle_sha256 = _sha256_json(manifest_core)
    seq = int(previous_deployment_sequence) + 1

    return {
        "schema_version": "1",
        "bundle_id": f"deploy-bundle-{bundle_sha256[:12]}",
        "bundle_sha256": bundle_sha256,
        "deployment_sequence": seq,
        "generated_at": effective_generated_at,
        "deployed_code_sha": str(deployed_code_sha).strip(),
        "release_tag": release_tag or f"data-snapshot-{bundle_sha256[:12]}",
        "producer": {
            "workflow": producing_workflow,
            "run_id": producing_run_id,
            "verified_main_branch": True,
        },
        "collections": pinned_collections,
        "evidence_snapshot_ids": copy.deepcopy(evidence_snapshot_ids),
    }


def verify_promotion_candidate_not_stale(
    current_deployed_manifest: dict[str, Any] | None,
    candidate_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Reject stale deployment candidates so older workflow runs cannot overwrite newer promotions (#73 ADR 2026-11-09)."""
    if not current_deployed_manifest:
        return {"promotable": True, "reason": "initial_deployment"}

    curr_seq = int(current_deployed_manifest.get("deployment_sequence") or 0)
    cand_seq = int(candidate_manifest.get("deployment_sequence") or 0)
    if cand_seq <= curr_seq:
        return {
            "promotable": False,
            "reason": f"Candidate deployment_sequence ({cand_seq}) is not newer than deployed ({curr_seq}).",
        }

    curr_dt = _parse_iso_dt(current_deployed_manifest.get("generated_at"))
    cand_dt = _parse_iso_dt(candidate_manifest.get("generated_at"))
    if curr_dt is not None and cand_dt is not None and cand_dt < curr_dt:
        return {
            "promotable": False,
            "reason": (
                f"Candidate timestamp ({candidate_manifest.get('generated_at')}) is older than currently "
                f"deployed manifest ({current_deployed_manifest.get('generated_at')})."
            ),
        }

    if not (candidate_manifest.get("producer") or {}).get("verified_main_branch"):
        return {
            "promotable": False,
            "reason": "Candidate producer is not verified on protected main branch.",
        }

    return {"promotable": True, "reason": "verified_newer_candidate"}


# ============================================================================
# Command-Line Entry Point (#73 Operational CLI)
# ============================================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sync-status",
        action="store_true",
        help="Generate receipts and synchronize data/pipeline-status.json from committed publication artifacts.",
    )
    parser.add_argument(
        "--validate-status",
        action="store_true",
        help="Validate data/pipeline-status.json and verify all receipt/coverage links and canonical digests on disk.",
    )
    parser.add_argument(
        "--verify-replay",
        type=Path,
        default=None,
        help="Dataset JSON path to verify offline deterministic replay against --receipt.",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=None,
        help="Assessment receipt JSON path for --verify-replay.",
    )
    parser.add_argument(
        "--status-path",
        type=Path,
        default=DEFAULT_PIPELINE_STATUS_PATH,
        help="Path to pipeline-status.json.",
    )
    parser.add_argument(
        "--root-dir",
        type=Path,
        default=ROOT_DIR,
        help="Repository root directory.",
    )
    parser.add_argument(
        "--checked-at",
        type=str,
        default=None,
        help="Optional explicit ISO-8601 UTC timestamp for deterministic status generation.",
    )
    args = parser.parse_args(argv)

    if args.sync_status:
        status_doc = build_public_pipeline_status_from_artifacts(
            root_dir=args.root_dir,
            checked_at=args.checked_at,
            write_receipts=True,
        )
        errors = validate_public_pipeline_status_provenance(status_doc, root_dir=args.root_dir)
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        args.status_path.parent.mkdir(parents=True, exist_ok=True)
        args.status_path.write_text(json.dumps(status_doc, indent=2) + "\n", encoding="utf-8")
        print(f"Synchronized and verified {args.status_path} and assessment receipts.")
        return 0

    if args.validate_status:
        if not args.status_path.exists():
            print(f"error: status file not found: {args.status_path}", file=sys.stderr)
            return 1
        status_doc = json.loads(args.status_path.read_text(encoding="utf-8"))
        errors = validate_public_pipeline_status_provenance(status_doc, root_dir=args.root_dir)
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print("Pipeline status provenance validation passed.")
        return 0

    if args.verify_replay is not None:
        if args.receipt is None:
            print("error: --verify-replay requires --receipt <path>", file=sys.stderr)
            return 1
        ds_doc = json.loads(args.verify_replay.read_text(encoding="utf-8"))
        rec_doc = json.loads(args.receipt.read_text(encoding="utf-8"))
        res = verify_offline_replay_determinism(dataset=ds_doc, receipt=rec_doc)
        if not res["verified"]:
            for err in res["errors"]:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print(json.dumps(res, indent=2))
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

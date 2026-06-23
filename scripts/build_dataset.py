#!/usr/bin/env python3
"""Build Risk Navigator scope dataset JSON from raw extracts + external signals."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sqlite3
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from common import (
    canonical_library_id,
    canonical_release,
    compare_versions,
    find_nearest_safe,
    is_ga_release,
    make_library_id,
    parse_library_id,
    risk_signal,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_ROOT = ROOT / "data" / "raw"
DEFAULT_OUTPUT_DIR = ROOT / "data"
DEFAULT_EXTERNAL_DIR = ROOT / "data" / "external"
DEFAULT_DEPSDEV_CACHE = DEFAULT_EXTERNAL_DIR / "depsdev_versions_cache.json"
DEFAULT_CVE_METADATA_CACHE = DEFAULT_EXTERNAL_DIR / "cve_metadata_cache.json"
DEFAULT_VULN_DB = ROOT / "data" / "vulns.db"
DEFAULT_OSV_SOURCE_ZIP = ROOT / "data" / "local" / "osv" / "all.zip"
DEFAULT_OSV_SOURCE_DIR = ROOT / "data" / "sources" / "osv"
TOOLING_QUALIFIERS = {"test", "build", "module-load"}
DEPSDEV_BASE = "https://api.deps.dev/v3"
OSV_BASE = "https://api.osv.dev/v1"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def metadata_path(path: Optional[Path]) -> str:
    if not path:
        return ""
    try:
        return str(path.resolve().relative_to(ROOT))
    except Exception:
        return str(path)


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path, default: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    if not path.exists():
        return default or {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_cve_metadata_entry(row: Dict[str, object], default_source: str = "unknown") -> Dict[str, str]:
    description = str(row.get("description") or row.get("details") or row.get("summary") or row.get("title") or "").strip()
    title = str(row.get("title") or row.get("summary") or "").strip()
    summary = str(row.get("summary") or row.get("title") or description).strip()
    published = str(
        row.get("published")
        or row.get("date_reported")
        or row.get("reported_at")
        or row.get("published_at")
        or row.get("date_published")
        or ""
    ).strip()
    modified = str(row.get("modified") or row.get("updated") or row.get("date_updated") or "").strip()
    source = str(row.get("source") or default_source).strip() or default_source
    return {
        "title": title,
        "summary": summary,
        "description": description,
        "published": published,
        "modified": modified,
        "source": source,
    }


def merge_cve_metadata(preferred: Dict[str, str], fallback: Dict[str, str], fallback_source: str = "unknown") -> Dict[str, str]:
    fb = normalize_cve_metadata_entry(fallback, fallback_source)
    out = dict(fb)
    for key in ("title", "summary", "description", "published", "modified", "source"):
        val = str(preferred.get(key) or "").strip()
        if val:
            out[key] = val
    return out


def load_cve_metadata_map(vuln_db: Path, external_dir: Path) -> Tuple[Dict[str, Dict[str, str]], Dict[str, object]]:
    """
    Load CVE metadata from local pipeline sources.

    Priority:
    1) Optional external overlay file: data/external/cve_metadata.json
    2) vuln_records table in local vuln DB (OSV-derived ingest fields)
    """
    out: Dict[str, Dict[str, str]] = {}
    stats = {
        "overlay_loaded": False,
        "overlay_entries": 0,
        "db_loaded": False,
        "db_entries": 0,
    }

    overlay_path = external_dir / "cve_metadata.json"
    overlay = read_json(overlay_path, {"data": {}})
    overlay_data = overlay.get("data") if isinstance(overlay, dict) else {}
    if isinstance(overlay_data, dict):
        for cve_id, row in overlay_data.items():
            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-") or not isinstance(row, dict):
                continue
            out[cve_id] = normalize_cve_metadata_entry(row, "external-overlay")
        stats["overlay_loaded"] = True
        stats["overlay_entries"] = len(out)

    if vuln_db.exists():
        conn = sqlite3.connect(vuln_db)
        conn.row_factory = sqlite3.Row
        try:
            col_rows = conn.execute("PRAGMA table_info(vuln_records)").fetchall()
            cols = {str(r["name"]) for r in col_rows if "name" in r.keys()}
            select_cols = ["cve_id", "summary", "raw_json"]
            for col in ("title", "details", "published", "modified", "source"):
                if col in cols:
                    select_cols.append(col)
            sql = f"SELECT {', '.join(select_cols)} FROM vuln_records WHERE cve_id LIKE 'CVE-%'"
            rows = conn.execute(sql).fetchall()
            for row in rows:
                cve_id = str(row["cve_id"] or "").strip()
                if not cve_id:
                    continue
                current = out.get(cve_id, {})
                raw_payload = {}
                raw_json = row["raw_json"] if "raw_json" in row.keys() else None
                if isinstance(raw_json, str) and raw_json.strip():
                    try:
                        parsed = json.loads(raw_json)
                        if isinstance(parsed, dict):
                            raw_payload = parsed
                    except json.JSONDecodeError:
                        raw_payload = {}

                row_meta = {
                    "title": str(row["title"] or "").strip() if "title" in row.keys() else "",
                    "summary": str(row["summary"] or "").strip(),
                    "description": str(row["details"] or "").strip() if "details" in row.keys() else "",
                    "published": str(row["published"] or "").strip() if "published" in row.keys() else "",
                    "modified": str(row["modified"] or "").strip() if "modified" in row.keys() else "",
                    "source": str(row["source"] or "").strip() if "source" in row.keys() else "osv",
                }

                # Backward compatibility: older DB snapshots keep only raw_json + summary.
                if not row_meta["title"] and isinstance(raw_payload.get("summary"), str):
                    row_meta["title"] = str(raw_payload.get("summary") or "").strip()
                if not row_meta["summary"] and isinstance(raw_payload.get("summary"), str):
                    row_meta["summary"] = str(raw_payload.get("summary") or "").strip()
                if not row_meta["description"] and isinstance(raw_payload.get("details"), str):
                    row_meta["description"] = str(raw_payload.get("details") or "").strip()
                if not row_meta["published"] and isinstance(raw_payload.get("published"), str):
                    row_meta["published"] = str(raw_payload.get("published") or "").strip()
                if not row_meta["modified"] and isinstance(raw_payload.get("modified"), str):
                    row_meta["modified"] = str(raw_payload.get("modified") or "").strip()

                out[cve_id] = merge_cve_metadata(current, row_meta, "osv")
            stats["db_loaded"] = True
            stats["db_entries"] = len(rows)
        finally:
            conn.close()

    return out, stats


def cve_metadata_has_core_fields(meta: Dict[str, str]) -> bool:
    has_text = bool(str(meta.get("summary") or "").strip() or str(meta.get("description") or "").strip())
    has_date = bool(str(meta.get("published") or "").strip() or str(meta.get("modified") or "").strip())
    return has_text and has_date


def fetch_osv_cve_metadata(cve_id: str, timeout_sec: float = 15.0) -> Dict[str, str]:
    cve = str(cve_id or "").strip()
    if not cve or not cve.startswith("CVE-"):
        return {}
    url = f"{OSV_BASE}/vulns/{quote(cve, safe='')}"
    req = Request(url, headers={"User-Agent": "risk-nav/1.0 (cve metadata enrichment)"})
    with urlopen(req, timeout=timeout_sec) as resp:
        payload = json.load(resp)
    if not isinstance(payload, dict):
        return {}
    return normalize_cve_metadata_entry(
        {
            "title": payload.get("summary"),
            "summary": payload.get("summary"),
            "description": payload.get("details"),
            "published": payload.get("published"),
            "modified": payload.get("modified"),
            "source": "osv-live",
        },
        "osv-live",
    )


def iter_osv_source_records(source_zip: Optional[Path], source_dir: Optional[Path]) -> Iterable[Dict[str, object]]:
    if source_zip and source_zip.exists():
        try:
            with zipfile.ZipFile(source_zip, "r") as archive:
                for name in archive.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        payload = json.loads(archive.read(name))
                    except (json.JSONDecodeError, KeyError):
                        continue
                    if isinstance(payload, dict):
                        yield payload
                    elif isinstance(payload, list):
                        for item in payload:
                            if isinstance(item, dict):
                                yield item
            return
        except zipfile.BadZipFile:
            pass

    if source_dir and source_dir.exists():
        for path in sorted(source_dir.rglob("*.json")):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                yield payload
            elif isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        yield item


def extract_cve_ids_from_osv_record(record: Dict[str, object]) -> List[str]:
    out: List[str] = []
    seen = set()

    rid = str(record.get("id") or "").strip()
    if rid.startswith("CVE-"):
        seen.add(rid)
        out.append(rid)

    aliases = record.get("aliases")
    if isinstance(aliases, list):
        for alias in aliases:
            cve = str(alias or "").strip()
            if cve.startswith("CVE-") and cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def enrich_cve_metadata_from_osv_source(
    cve_ids: Sequence[str],
    cve_meta_map: Dict[str, Dict[str, str]],
    source_zip: Optional[Path] = None,
    source_dir: Optional[Path] = None,
) -> Dict[str, object]:
    target_ids = {str(cve_id or "").strip() for cve_id in cve_ids if str(cve_id or "").strip().startswith("CVE-")}
    unresolved = {cve_id for cve_id in target_ids if not cve_metadata_has_core_fields(cve_meta_map.get(cve_id, {}))}

    stats = {
        "enabled": True,
        "source_zip": metadata_path(source_zip),
        "source_dir": metadata_path(source_dir),
        "source_zip_exists": bool(source_zip and source_zip.exists()),
        "source_dir_exists": bool(source_dir and source_dir.exists()),
        "considered": len(target_ids),
        "unresolved_before": len(unresolved),
        "records_scanned": 0,
        "records_matched": 0,
        "filled": 0,
        "unresolved_after": len(unresolved),
    }
    if not unresolved:
        return stats
    if not stats["source_zip_exists"] and not stats["source_dir_exists"]:
        stats["enabled"] = False
        return stats

    for record in iter_osv_source_records(source_zip=source_zip, source_dir=source_dir):
        stats["records_scanned"] += 1
        matched_ids = [cve_id for cve_id in extract_cve_ids_from_osv_record(record) if cve_id in unresolved]
        if not matched_ids:
            continue
        stats["records_matched"] += 1
        osv_meta = normalize_cve_metadata_entry(
            {
                "title": record.get("summary"),
                "summary": record.get("summary"),
                "description": record.get("details"),
                "published": record.get("published"),
                "modified": record.get("modified"),
                "source": "osv-source",
            },
            "osv-source",
        )
        for cve_id in matched_ids:
            merged = merge_cve_metadata(cve_meta_map.get(cve_id, {}), osv_meta, "osv-source")
            cve_meta_map[cve_id] = merged
            if cve_metadata_has_core_fields(merged):
                unresolved.discard(cve_id)
                stats["filled"] += 1
        if not unresolved:
            break

    stats["unresolved_after"] = len(unresolved)
    return stats


def enrich_missing_cve_metadata(
    cve_ids: Sequence[str],
    cve_meta_map: Dict[str, Dict[str, str]],
    cache_path: Path,
    enabled: bool = True,
    timeout_sec: float = 15.0,
) -> Dict[str, object]:
    cache = read_json_obj(cache_path)
    cache_data = cache.get("data")
    if not isinstance(cache_data, dict):
        cache_data = {}

    stats = {
        "enabled": bool(enabled),
        "considered": 0,
        "cache_hits": 0,
        "fetched": 0,
        "failed": 0,
        "filled_from_cache": 0,
    }

    changed = False
    for raw_id in cve_ids:
        cve_id = str(raw_id or "").strip()
        if not cve_id.startswith("CVE-"):
            continue
        stats["considered"] += 1

        current = cve_meta_map.get(cve_id, {})
        if cve_metadata_has_core_fields(current):
            continue

        cached = cache_data.get(cve_id)
        if isinstance(cached, dict):
            stats["cache_hits"] += 1
            merged_cached = merge_cve_metadata(current, cached, "osv-live-cache")
            cve_meta_map[cve_id] = merged_cached
            if cve_metadata_has_core_fields(merged_cached):
                stats["filled_from_cache"] += 1
                continue

        if not enabled:
            continue

        try:
            fetched = fetch_osv_cve_metadata(cve_id, timeout_sec=timeout_sec)
            if fetched:
                cve_meta_map[cve_id] = merge_cve_metadata(cve_meta_map.get(cve_id, {}), fetched, "osv-live")
                cache_data[cve_id] = {
                    "title": fetched.get("title", ""),
                    "summary": fetched.get("summary", ""),
                    "description": fetched.get("description", ""),
                    "published": fetched.get("published", ""),
                    "modified": fetched.get("modified", ""),
                    "source": "osv-live",
                    "fetched_at": now_iso(),
                }
                stats["fetched"] += 1
                changed = True
            else:
                stats["failed"] += 1
        except (HTTPError, URLError, TimeoutError):
            stats["failed"] += 1
        except Exception:
            stats["failed"] += 1

    if changed or not cache_path.exists():
        write_json_obj(
            cache_path,
            {
                "fetched_at": now_iso(),
                "source": "osv.dev v1",
                "data": cache_data,
            },
        )

    return stats


def to_float(val: object, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def to_int(val: object, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def parse_aliases_field(val: object) -> List[str]:
    raw = str(val or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            out = []
            for item in parsed:
                s = str(item or "").strip()
                if s:
                    out.append(s)
            return out
    except json.JSONDecodeError:
        pass
    return [chunk.strip() for chunk in raw.split("|") if chunk.strip()]


def read_json_obj(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def write_json_obj(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))


def normalize_pypi_name(name: str) -> str:
    # PEP 503 normalization.
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def depsdev_package_key(namespace: str, meta: str, proj: str) -> Optional[Tuple[str, str]]:
    ns = (namespace or "").strip().lower()
    m = (meta or "").strip()
    p = (proj or "").strip()
    if not p and not m:
        return None

    if ns == "maven":
        if not m or not p:
            return None
        return ("maven", f"{m}:{p}")
    if ns == "pypi":
        return ("pypi", normalize_pypi_name(p))
    if ns == "npm":
        if m and m.startswith("@"):
            return ("npm", f"{m}/{p}")
        return ("npm", p)
    if ns == "nuget":
        return ("nuget", p.lower())
    if ns == "cargo":
        return ("cargo", p)
    if ns == "rubygems":
        return ("rubygems", p)
    if ns == "go":
        if m:
            return ("go", f"{m}/{p}" if p else m)
        return ("go", p)
    return None


def fetch_depsdev_versions(system: str, package_name: str, timeout_sec: float = 20.0) -> Dict[str, str]:
    encoded_name = quote(package_name, safe="")
    url = f"{DEPSDEV_BASE}/systems/{quote(system, safe='')}/packages/{encoded_name}"
    req = Request(url, headers={"User-Agent": "risk-nav/1.0 (local pipeline release enrichment)"})
    with urlopen(req, timeout=timeout_sec) as resp:
        payload = json.load(resp)

    out: Dict[str, str] = {}
    for row in payload.get("versions", []) if isinstance(payload, dict) else []:
        if not isinstance(row, dict):
            continue
        version_key = row.get("versionKey") if isinstance(row.get("versionKey"), dict) else {}
        version = str(version_key.get("version", "")).strip()
        published = str(row.get("publishedAt", "")).strip()
        if version and published:
            out[version] = published
    return out


def enrich_version_rows_from_depsdev(
    version_by_pkg: Dict[Tuple[str, str, str], List[Dict[str, object]]],
    cache_path: Path,
    timeout_sec: float = 20.0,
) -> Dict[str, object]:
    cache = read_json_obj(cache_path)
    entries = cache.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    changed = False

    stats = {
        "enabled": True,
        "packages_considered": 0,
        "packages_reused_cache": 0,
        "packages_fetched": 0,
        "packages_failed": 0,
        "timestamps_applied": 0,
    }

    def newest_release(namespace: str, versions: Iterable[str]) -> Optional[str]:
        best: Optional[str] = None
        for ver in versions:
            v = str(ver).strip()
            if not v:
                continue
            if best is None:
                best = v
                continue
            cmpv = compare_versions(namespace, v, best)
            if cmpv is None:
                continue
            if cmpv > 0:
                best = v
        return best

    for (namespace, meta, proj), chain in sorted(version_by_pkg.items()):
        pkg = depsdev_package_key(namespace, meta, proj)
        if not pkg:
            continue
        system, package_name = pkg
        cache_key = f"{system}|{package_name}"
        stats["packages_considered"] += 1

        observed_versions = {str(row.get("release", "")).strip() for row in chain if str(row.get("release", "")).strip()}
        entry = entries.get(cache_key) if isinstance(entries, dict) else None
        cached_versions = {}
        if isinstance(entry, dict) and isinstance(entry.get("versions"), dict):
            cached_versions = {
                str(k): str(v)
                for k, v in entry.get("versions", {}).items()
                if str(k).strip() and str(v).strip()
            }

        observed_max = newest_release(namespace, observed_versions)
        cached_max = newest_release(namespace, cached_versions.keys())
        needs_refresh = not cached_versions
        if not needs_refresh and observed_max and cached_max:
            cmpv = compare_versions(namespace, observed_max, cached_max)
            needs_refresh = cmpv == 1
        elif not needs_refresh and observed_max and not cached_max:
            needs_refresh = True
        if not needs_refresh:
            stats["packages_reused_cache"] += 1
        else:
            try:
                fetched = fetch_depsdev_versions(system, package_name, timeout_sec=timeout_sec)
                entries[cache_key] = {
                    "system": system,
                    "package_name": package_name,
                    "versions": fetched,
                    "fetched_at": now_iso(),
                    "status": "ok",
                }
                cached_versions = fetched
                changed = True
                stats["packages_fetched"] += 1
            except HTTPError as exc:
                entries[cache_key] = {
                    "system": system,
                    "package_name": package_name,
                    "versions": cached_versions,
                    "fetched_at": now_iso(),
                    "status": f"http_{exc.code}",
                }
                changed = True
                stats["packages_failed"] += 1
            except URLError:
                stats["packages_failed"] += 1
            except TimeoutError:
                stats["packages_failed"] += 1
            except Exception:
                stats["packages_failed"] += 1

        for row in chain:
            release = str(row.get("release", "")).strip()
            if not release:
                continue
            published = cached_versions.get(release, "")
            if published:
                row["release_date"] = published
                row["release_published_at"] = published
                row["release_date_source"] = "deps.dev"
                stats["timestamps_applied"] += 1

    cache_payload = {
        "fetched_at": now_iso(),
        "source": "deps.dev v3",
        "entries": entries,
    }
    if changed or not cache_path.exists():
        write_json_obj(cache_path, cache_payload)
    return stats


def framework_memberships(library: Dict[str, object]) -> List[str]:
    namespace = str(library.get("namespace", ""))
    meta = str(library.get("meta", ""))
    proj = str(library.get("proj", ""))

    tags = []
    if namespace == "maven" and meta.startswith("org.springframework.boot"):
        tags.append("spring-boot")
    if namespace == "maven" and meta.startswith("org.springframework.security"):
        tags.append("spring-security")
    if namespace == "maven" and meta.startswith("org.springframework"):
        tags.append("spring-framework")
    if namespace == "maven" and meta.startswith("io.netty"):
        tags.append("netty")
    if namespace == "rpm":
        tags.append("rhel-base")
    if namespace == "maven" and "jackson" in meta:
        tags.append("jackson")

    if not tags:
        tags.append("other")
    return tags


def sanitize_sortable_cves(cves: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    def sort_key(row: Dict[str, object]):
        return (
            0 if row.get("kev") else 1,
            -to_float(row.get("epss"), 0.0),
            -to_float(row.get("cvss"), 0.0),
            str(row.get("cve_id", "")),
        )

    out = sorted(list(cves), key=sort_key)
    return out[:50]


def load_raw_scope(raw_root: Path, scope: str) -> Dict[str, List[Dict[str, str]]]:
    scope_dir = raw_root / scope
    return {
        "projects": read_csv(scope_dir / "01-consumer-projects.csv"),
        "dep_edges": read_csv(scope_dir / "02-dep-edges.csv"),
        "cve_libs": read_csv(scope_dir / "03-cve-libs.csv"),
        "version_chain": read_csv(scope_dir / "04-version-chain.csv"),
        "amplifiers": read_csv(scope_dir / "05-amplifiers.csv"),
        "cve_edges": read_csv(scope_dir / "06-cve-edges.csv"),
    }


def build_dataset(
    scope: str,
    raw_root: Path,
    external_dir: Path,
    output_dir: Path,
    vuln_db: Path,
    exclude_library_namespaces: Optional[Sequence[str]] = None,
    depsdev_cache_path: Optional[Path] = None,
    cve_metadata_cache_path: Optional[Path] = None,
    osv_source_zip: Optional[Path] = None,
    osv_source_dir: Optional[Path] = None,
    enrich_release_dates: bool = True,
    enrich_cve_metadata_online: bool = True,
    amplifiers_preaggregated: bool = False,
    meta_overlay: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    raw = load_raw_scope(raw_root, scope)
    excluded_ns = {ns.strip().lower() for ns in (exclude_library_namespaces or []) if ns and ns.strip()}

    projects = raw["projects"]
    dep_edges_all = raw["dep_edges"]
    dep_edges = [edge for edge in dep_edges_all if edge.get("qualifier", "").strip().lower() not in TOOLING_QUALIFIERS]
    if excluded_ns:
        dep_edges = [
            edge
            for edge in dep_edges
            if (parse_library_id(edge.get("library_id", ""))[0].lower() if edge.get("library_id") else "") not in excluded_ns
        ]

    cve_libs_rows = raw["cve_libs"]
    cve_edges_rows = raw["cve_edges"]
    version_rows = raw["version_chain"]
    amp_rows = raw["amplifiers"]

    kev = read_json(external_dir / "kev.json", {"data": {}})
    epss = read_json(external_dir / "epss.json", {"data": {}})
    cve_meta_map, cve_meta_stats = load_cve_metadata_map(vuln_db=vuln_db, external_dir=external_dir)
    cve_ids_in_scope = sorted({str(row.get("cve_id", "")).strip() for row in cve_edges_rows if str(row.get("cve_id", "")).strip()})
    cve_osv_source_stats = enrich_cve_metadata_from_osv_source(
        cve_ids=cve_ids_in_scope,
        cve_meta_map=cve_meta_map,
        source_zip=osv_source_zip or DEFAULT_OSV_SOURCE_ZIP,
        source_dir=osv_source_dir or DEFAULT_OSV_SOURCE_DIR,
    )
    cve_online_stats = enrich_missing_cve_metadata(
        cve_ids=cve_ids_in_scope,
        cve_meta_map=cve_meta_map,
        cache_path=cve_metadata_cache_path or DEFAULT_CVE_METADATA_CACHE,
        enabled=bool(enrich_cve_metadata_online),
    )
    kev_map = kev.get("data") if isinstance(kev.get("data"), dict) else {}
    epss_map = epss.get("data") if isinstance(epss.get("data"), dict) else {}

    project_by_id = {row["id"]: row for row in projects if row.get("id")}

    normalized_dep_edges: List[Dict[str, str]] = []
    for edge in dep_edges:
        normalized = dict(edge)
        lid = normalized.get("library_id", "")
        if lid:
            normalized["library_id"] = canonical_library_id(lid)
        parent_id = normalized.get("parent_id", "")
        if parent_id:
            normalized["parent_id"] = canonical_library_id(parent_id)
        normalized_dep_edges.append(normalized)
    dep_edges = normalized_dep_edges

    dept_counts = Counter()
    for proj in projects:
        dept = proj.get("department", "Unknown") or "Unknown"
        dept_counts[dept] += 1

    dep_by_lib: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    dep_by_consumer: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for edge in dep_edges:
        lid = edge.get("library_id", "")
        cid = edge.get("consumer_id", "")
        if lid:
            dep_by_lib[lid].append(edge)
        if cid:
            dep_by_consumer[cid].append(edge)

    cves_by_lib: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    seen_cve_by_lib: set[Tuple[str, str]] = set()
    for row in cve_edges_rows:
        library_id = row.get("library_id", "")
        if not library_id:
            continue
        library_id = canonical_library_id(library_id)
        cve_id = row.get("cve_id", "")
        seen_key = (library_id, cve_id)
        if seen_key in seen_cve_by_lib:
            continue
        seen_cve_by_lib.add(seen_key)
        epss_entry = epss_map.get(cve_id, {}) if isinstance(epss_map, dict) else {}
        cve_meta = cve_meta_map.get(cve_id, {})
        cve_info = {
            "cve_id": cve_id,
            "cvss": to_float(row.get("cvss_base"), 0.0),
            "exploit": row.get("exploitability", "UNPROVEN"),
            "priority": row.get("priority", "P4"),
            "kev": cve_id in kev_map,
            "epss": to_float(epss_entry.get("epss"), 0.0),
            "epss_pctile": to_float(epss_entry.get("percentile"), 0.0),
            "title": str(cve_meta.get("title") or ""),
            "summary": str(cve_meta.get("summary") or ""),
            "description": str(cve_meta.get("description") or ""),
            "published": str(cve_meta.get("published") or ""),
            "modified": str(cve_meta.get("modified") or ""),
            "cve_source": str(cve_meta.get("source") or "unknown"),
        }
        cves_by_lib[library_id].append(cve_info)

    version_by_pkg: Dict[Tuple[str, str, str], List[Dict[str, object]]] = defaultdict(list)
    version_by_pkg_release: Dict[Tuple[str, str, str], Dict[str, Dict[str, object]]] = defaultdict(dict)
    for row in version_rows:
        namespace = row.get("namespace", "")
        key = (namespace, row.get("meta", ""), row.get("proj", ""))
        release = canonical_release(namespace, row.get("release", ""))
        if not release:
            continue
        next_item = {
            "release": release,
            "release_id": to_int(row.get("release_id"), 0),
            "max_cvss": to_float(row.get("max_cvss"), 0.0),
            "cve_count": to_int(row.get("cve_count"), 0),
        }
        current = version_by_pkg_release[key].get(release)
        if not current:
            version_by_pkg_release[key][release] = next_item
            continue
        current["release_id"] = min(to_int(current.get("release_id"), 0), next_item["release_id"])
        current["max_cvss"] = max(to_float(current.get("max_cvss"), 0.0), next_item["max_cvss"])
        current["cve_count"] = max(to_int(current.get("cve_count"), 0), next_item["cve_count"])

    for key, by_release in version_by_pkg_release.items():
        version_by_pkg[key] = list(by_release.values())

    for chain in version_by_pkg.values():
        chain.sort(key=lambda x: x.get("release_id", 0))

    release_enrichment_stats = {"enabled": False}
    if enrich_release_dates:
        release_enrichment_stats = enrich_version_rows_from_depsdev(
            version_by_pkg=version_by_pkg,
            cache_path=depsdev_cache_path or DEFAULT_DEPSDEV_CACHE,
        )

    amplifiers_by_lib: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in amp_rows:
        lid = row.get("cve_lib_id", "")
        aid = row.get("amplifier_id", "")
        if not lid or not aid:
            continue
        lid = canonical_library_id(lid)
        aid = canonical_library_id(aid)
        a_ns, a_meta, a_proj, a_rel = parse_library_id(aid)
        amplifiers_by_lib[lid].append(
            {
                "namespace": a_ns,
                "meta": a_meta,
                "proj": a_proj,
                "release": a_rel,
                "amplifier_consumer_count": to_int(row.get("root_projects_affected"), 0),
                "amplifier_id": aid,
            }
        )

    # Infer amplifiers from parent_id if CSV was not generated.
    if not amplifiers_by_lib:
        inferred: Dict[Tuple[str, str], set] = defaultdict(set)
        for edge in dep_edges:
            if str(edge.get("direct", "0")) != "0":
                continue
            parent = edge.get("parent_id", "")
            lid = edge.get("library_id", "")
            cid = edge.get("consumer_id", "")
            if parent and lid and cid:
                inferred[(lid, parent)].add(cid)

        for (lid, aid), consumers in inferred.items():
            a_ns, a_meta, a_proj, a_rel = parse_library_id(aid)
            amplifiers_by_lib[lid].append(
                {
                    "namespace": a_ns,
                    "meta": a_meta,
                    "proj": a_proj,
                    "release": a_rel,
                    "amplifier_consumer_count": len(consumers),
                    "amplifier_id": aid,
                }
            )

    libraries: List[Dict[str, object]] = []
    effort_counts = Counter()

    seen_library_ids: set[str] = set()
    for row in cve_libs_rows:
        lid = row.get("library_id", "")
        if not lid:
            continue
        lid = canonical_library_id(lid)
        if lid in seen_library_ids:
            continue
        seen_library_ids.add(lid)

        lib_edges = dep_by_lib.get(lid, [])
        if not lib_edges:
            # The vulnerable lib is not consumed in this scope after tooling filter.
            continue

        namespace, meta, proj, release = parse_library_id(lid)
        if namespace.lower() in excluded_ns:
            continue

        consumers_all = sorted({e.get("consumer_id", "") for e in lib_edges if e.get("consumer_id", "")})
        consumers_direct = sorted(
            {
                e.get("consumer_id", "")
                for e in lib_edges
                if e.get("consumer_id", "") and str(e.get("direct", "0")) == "1"
            }
        )

        total_consumer_count = len(consumers_all)
        direct_count = len(consumers_direct)
        transitive_count = max(0, total_consumer_count - direct_count)

        cves = sanitize_sortable_cves(cves_by_lib.get(lid, []))
        kev_ids = [row["cve_id"] for row in cves if row.get("kev")]
        epss_values = [to_float(item.get("epss"), 0.0) for item in cves]

        pkg_key = (namespace, meta, proj)
        chain = []
        for chain_row in version_by_pkg.get(pkg_key, []):
            item = dict(chain_row)
            item["is_safe"] = bool(item.get("max_cvss", 0.0) < 7.0 and is_ga_release(str(item.get("release", ""))))
            chain.append(item)

        current_release_row = next((item for item in chain if str(item.get("release", "")) == release), {})
        current_release_date = str(current_release_row.get("release_date", "")).strip()

        nearest_safe, max_patch, distance = find_nearest_safe(namespace, release, chain)
        if nearest_safe is None and distance == "DEAD_END":
            effort_class = "DEAD_END"
        else:
            effort_class = distance

        amplifiers = sorted(
            amplifiers_by_lib.get(lid, []),
            key=lambda x: (-to_int(x.get("amplifier_consumer_count"), 0), x.get("proj", "")),
        )[:20]
        top_amp = amplifiers[0] if amplifiers else None

        lib_obj = {
            "id": lid,
            "namespace": namespace,
            "meta": meta,
            "proj": proj,
            "release": release,
            "max_cvss": round(to_float(row.get("max_cvss"), 0.0), 1),
            "cve_count": len(cves),
            "highest_priority": row.get("highest_priority", "P4"),
            "max_exploitability": row.get("max_exploitability", "UNPROVEN"),
            "cves": cves,
            "cves_truncated": len(cves_by_lib.get(lid, [])) > 50,
            "is_kev_listed": len(kev_ids) > 0,
            "kev_cve_count": len(kev_ids),
            "kev_cve_ids": kev_ids,
            "epss_max": round(max(epss_values) if epss_values else 0.0, 6),
            "epss_avg": round(sum(epss_values) / len(epss_values), 6) if epss_values else 0.0,
            "epss_count": len([x for x in epss_values if x > 0.0]),
            "library_itso": {
                "tai_system": row.get("lib_tai_system", "unknown"),
                "primary_owner": row.get("lib_primary_owner", "unknown@example.org"),
                "department": row.get("lib_dept", "Unknown"),
            },
            "consumer_project_ids": consumers_all[:200],
            "consumer_project_ids_truncated": len(consumers_all) > 200,
            "direct_consumer_project_ids": consumers_direct,
            "direct_consumer_count": direct_count,
            "transitive_consumer_count": transitive_count,
            "total_consumer_count": total_consumer_count,
            "transitive_heaviness_ratio": round(transitive_count / total_consumer_count, 6) if total_consumer_count else 0.0,
            "top_amplifier": {
                "namespace": top_amp["namespace"],
                "meta": top_amp["meta"],
                "proj": top_amp["proj"],
                "release": top_amp["release"],
                "amplifier_consumer_count": top_amp["amplifier_consumer_count"],
            }
            if top_amp
            else None,
            "all_amplifiers": [
                {
                    "namespace": item["namespace"],
                    "meta": item["meta"],
                    "proj": item["proj"],
                    "release": item["release"],
                    "amplifier_consumer_count": item["amplifier_consumer_count"],
                }
                for item in amplifiers
            ],
            "all_amplifiers_truncated": len(amplifiers_by_lib.get(lid, [])) > 20,
            "version_chain": chain,
            "release_date": current_release_date,
            "nearest_safe_version": nearest_safe,
            "max_safe_patch_same_minor": max_patch,
            "distance_to_safe": distance,
            "effort_class": effort_class,
            "risk_signal": round(
                risk_signal(
                    max_cvss=to_float(row.get("max_cvss"), 0.0),
                    consumers=total_consumer_count,
                    kev=len(kev_ids) > 0,
                    epss_max=max(epss_values) if epss_values else 0.0,
                ),
                6,
            ),
            "frameworks": framework_memberships({"namespace": namespace, "meta": meta, "proj": proj}),
        }

        effort_counts[effort_class] += 1
        libraries.append(lib_obj)

    libraries.sort(key=lambda x: x.get("risk_signal", 0.0), reverse=True)

    vulnerable_library_ids = {lib["id"] for lib in libraries}

    amplifier_cluster_map: Dict[str, Dict[str, object]] = {}
    for lib in libraries:
        lid = lib["id"]
        lib_cve_count = to_int(lib.get("cve_count"), 0)
        for amp in lib.get("all_amplifiers", []):
            amp_id = f"{amp['namespace']}|{amp['meta']}|{amp['proj']}"
            label = f"{amp['namespace']}/{amp['meta']}/{amp['proj']}"
            state = amplifier_cluster_map.setdefault(
                amp_id,
                {
                    "amplifier_id": amp_id,
                    "amplifier_label": label,
                    "amplified_libraries": set(),
                    "consumer_project_ids": set(),
                    "cve_count_total": 0,
                    "consumer_project_count_hint": 0,
                },
            )
            state["amplified_libraries"].add(lid)
            state["cve_count_total"] += lib_cve_count
            state["consumer_project_count_hint"] = max(
                to_int(state.get("consumer_project_count_hint"), 0),
                to_int(amp.get("amplifier_consumer_count"), 0),
            )

            # union affected consumers by checking transitive edges with same parent identity
            for edge in dep_by_lib.get(lid, []):
                if str(edge.get("direct", "0")) != "0":
                    continue
                parent_id = edge.get("parent_id", "")
                if not parent_id:
                    continue
                p_ns, p_meta, p_proj, _ = parse_library_id(parent_id)
                if (p_ns, p_meta, p_proj) == (amp["namespace"], amp["meta"], amp["proj"]):
                    cid = edge.get("consumer_id", "")
                    if cid:
                        state["consumer_project_ids"].add(cid)

    amplifier_clusters = []
    for state in amplifier_cluster_map.values():
        inferred_count = len(state["consumer_project_ids"])
        preagg_count = to_int(state.get("consumer_project_count_hint"), 0)
        affected_count = inferred_count
        if amplifiers_preaggregated or inferred_count == 0:
            affected_count = max(inferred_count, preagg_count)
        amplifier_clusters.append(
            {
                "amplifier_id": state["amplifier_id"],
                "amplifier_label": state["amplifier_label"],
                "amplified_libraries": sorted(state["amplified_libraries"]),
                "consumer_project_count_affected": affected_count,
                "cve_count_total": state["cve_count_total"],
            }
        )

    amplifier_clusters.sort(key=lambda x: (-x["consumer_project_count_affected"], -x["cve_count_total"]))

    project_rollups: List[Dict[str, object]] = []
    for proj in projects:
        pid = proj.get("id", "")
        pedges = dep_by_consumer.get(pid, [])
        vuln_ids = sorted({e.get("library_id", "") for e in pedges if e.get("library_id", "") in vulnerable_library_ids})
        direct_vuln_ids = sorted(
            {e.get("library_id", "") for e in pedges if e.get("library_id", "") in vulnerable_library_ids and str(e.get("direct", "0")) == "1"}
        )
        project_rollups.append(
            {
                "id": pid,
                "namespace": proj.get("namespace", ""),
                "meta": proj.get("meta", ""),
                "proj": proj.get("proj", ""),
                "release": proj.get("release", ""),
                "project_ref": (proj.get("project_ref", "") or f"{proj.get('namespace','')}/{proj.get('meta','')}/{proj.get('proj','')}"),
                "aliases": parse_aliases_field(proj.get("aliases", "")),
                "eonid": proj.get("eonid", ""),
                "department": proj.get("department", "Unknown"),
                "tai_system": proj.get("tai_system", ""),
                "vulnerable_library_ids": vuln_ids,
                "vulnerable_library_count": len(vuln_ids),
                "direct_vulnerable_library_count": len(direct_vuln_ids),
                "transitive_vulnerable_library_count": max(0, len(vuln_ids) - len(direct_vuln_ids)),
                "max_cvss": max((next((lib["max_cvss"] for lib in libraries if lib["id"] == lid), 0.0) for lid in vuln_ids), default=0.0),
                "kev_vulnerability_count": sum(
                    1
                    for lid in vuln_ids
                    for lib in libraries
                    if lib["id"] == lid and lib.get("is_kev_listed")
                ),
            }
        )

    project_rollups.sort(key=lambda x: (-x["vulnerable_library_count"], -x["max_cvss"], x["id"]))

    dataset = {
        "meta": {
            "scope_type": "department",
            "scope_name": scope,
            "scope_label": "OSERA Demo Data" if scope == "finos-sample-platform" else scope,
            "division": "OSERA",
            "division_short": "OSERA",
            "branding": {
                "primary": {
                    "label": "\u00b7 OSERA",
                },
                "attribution": {
                    "text": "A FINOS community project.",
                    "url": "https://github.com/finos-backpatch/community",
                },
            },
            "extracted_at": now_iso(),
            "filters_applied": {
                "tooling_qualifiers_excluded": sorted(list(TOOLING_QUALIFIERS)),
                "library_namespaces_excluded": sorted(list(excluded_ns)),
                "cvss_min": 0.01,
            },
            "external_signals": {
                "kev_loaded": bool(kev_map),
                "epss_loaded": bool(epss_map),
                "fetched_at": str(kev.get("fetched_at") or epss.get("fetched_at") or now_iso()),
                "kev_total_entries": len(kev_map),
                "epss_total_entries": len(epss_map),
                "cve_metadata": cve_meta_stats,
                "cve_metadata_osv_source_enrichment": cve_osv_source_stats,
                "cve_metadata_online_enrichment": cve_online_stats,
                "release_enrichment": release_enrichment_stats,
            },
            "counts": {
                "consumer_projects": len(projects),
                "distinct_cve_libraries": len(libraries),
                "distinct_amplifier_clusters": len(amplifier_clusters),
                "kev_listed_libraries": sum(1 for lib in libraries if lib.get("is_kev_listed")),
                "effort_class_distribution": {
                    "PATCH": effort_counts.get("PATCH", 0),
                    "MINOR": effort_counts.get("MINOR", 0),
                    "MAJOR": effort_counts.get("MAJOR", 0),
                    "DEAD_END": effort_counts.get("DEAD_END", 0),
                    "UNKNOWN": effort_counts.get("UNKNOWN", 0),
                },
            },
        },
        "departments": [{"name": name, "project_count": count} for name, count in sorted(dept_counts.items())],
        "consumer_projects": project_rollups,
        "libraries": libraries,
        "amplifier_clusters": amplifier_clusters,
    }
    if isinstance(meta_overlay, dict):
        dataset_meta = dataset.get("meta")
        if isinstance(dataset_meta, dict):
            dataset_meta.update(meta_overlay)

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"{scope}.json"
    with open(out_file, "w", encoding="utf-8") as handle:
        json.dump(dataset, handle, separators=(",", ":"))

    return dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--external-dir", type=Path, default=DEFAULT_EXTERNAL_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--vuln-db", type=Path, default=DEFAULT_VULN_DB)
    parser.add_argument("--depsdev-cache", type=Path, default=DEFAULT_DEPSDEV_CACHE)
    parser.add_argument("--cve-metadata-cache", type=Path, default=DEFAULT_CVE_METADATA_CACHE)
    parser.add_argument("--osv-source-zip", type=Path, default=DEFAULT_OSV_SOURCE_ZIP)
    parser.add_argument("--osv-source-dir", type=Path, default=DEFAULT_OSV_SOURCE_DIR)
    parser.add_argument(
        "--no-enrich-release-dates",
        action="store_true",
        help="Disable deps.dev release-date enrichment.",
    )
    parser.add_argument(
        "--no-enrich-cve-metadata-online",
        action="store_true",
        help="Disable OSV live CVE metadata backfill for missing summary/date fields.",
    )
    parser.add_argument(
        "--exclude-library-namespaces",
        default="",
        help="Comma-separated library namespaces to exclude from dataset (e.g. pypi,rpm,oci,docker)",
    )
    parser.add_argument(
        "--meta-overlay",
        type=Path,
        default=None,
        help="Optional JSON file merged shallowly into dataset.meta at build time.",
    )
    parser.add_argument(
        "--amplifiers-preaggregated",
        action="store_true",
        help="Prefer 05-amplifiers.csv root_projects_affected hints when parent_id-level edge attribution is sparse.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    excluded = [x.strip() for x in str(args.exclude_library_namespaces or "").split(",") if x.strip()]
    meta_overlay = read_json(args.meta_overlay, {}) if args.meta_overlay else None
    dataset = build_dataset(
        args.scope,
        args.raw_root,
        args.external_dir,
        args.output_dir,
        args.vuln_db,
        exclude_library_namespaces=excluded,
        depsdev_cache_path=args.depsdev_cache,
        cve_metadata_cache_path=args.cve_metadata_cache,
        osv_source_zip=args.osv_source_zip,
        osv_source_dir=args.osv_source_dir,
        enrich_release_dates=not bool(args.no_enrich_release_dates),
        enrich_cve_metadata_online=not bool(args.no_enrich_cve_metadata_online),
        amplifiers_preaggregated=bool(args.amplifiers_preaggregated),
        meta_overlay=meta_overlay if isinstance(meta_overlay, dict) else None,
    )
    counts = dataset.get("meta", {}).get("counts", {})
    print(json.dumps(counts, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Ingest OSV-like vulnerability records into SQLite for Risk Navigator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

from common import split_coords

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_DIR = ROOT / "data" / "sources" / "osv"
DEFAULT_SOURCE_ZIP = ROOT / "data" / "local" / "osv" / "all.zip"
DEFAULT_DB = ROOT / "data" / "vulns.db"


@dataclass
class VulnVersionEdge:
    cve_id: str
    osv_id: str
    namespace: str
    meta: str
    proj: str
    release: str
    cvss: float
    exploitability: str
    priority: str


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def metadata_path_for_db(db_path: Path) -> Path:
    return db_path.with_suffix(db_path.suffix + ".meta.json")


def read_json_file(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def write_json_file(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def vector_to_base_score(vector: str) -> float:
    """Best-effort CVSS base score parser from vector string."""

    if not vector or not vector.startswith("CVSS:"):
        return 0.0
    # Heuristic conversion by known severity bands if precise parser unavailable.
    metric_pairs = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        metric_pairs[k] = v

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metric_pairs.get("AV", "L"), 0.55)
    ac = {"L": 0.77, "H": 0.44}.get(metric_pairs.get("AC", "H"), 0.44)
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
    scope_changed = metric_pairs.get("S", "U") == "C"
    pr = (pr_c if scope_changed else pr_u).get(metric_pairs.get("PR", "L"), 0.62)
    ui = {"N": 0.85, "R": 0.62}.get(metric_pairs.get("UI", "R"), 0.62)

    conf = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metric_pairs.get("C", "N"), 0.0)
    integ = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metric_pairs.get("I", "N"), 0.0)
    avail = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metric_pairs.get("A", "N"), 0.0)

    impact = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if scope_changed:
        impact_sub = 7.52 * (impact - 0.029) - 3.25 * ((impact - 0.02) ** 15)
    else:
        impact_sub = 6.42 * impact
    exploitability = 8.22 * av * ac * pr * ui

    if impact_sub <= 0:
        return 0.0

    if scope_changed:
        score = min(10.0, 1.08 * (impact_sub + exploitability))
    else:
        score = min(10.0, impact_sub + exploitability)
    return round(score * 10) / 10.0


def priority_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    return "P4"


def exploitability_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "FUNCTIONAL"
    if score >= 7.0:
        return "POC"
    return "UNPROVEN"


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vuln_records (
            cve_id TEXT PRIMARY KEY,
            osv_id TEXT,
            summary TEXT,
            title TEXT,
            details TEXT,
            published TEXT,
            modified TEXT,
            source TEXT,
            cvss REAL,
            priority TEXT,
            exploitability TEXT,
            raw_json TEXT,
            ingested_at TEXT
        );

        CREATE TABLE IF NOT EXISTS vuln_version_edges (
            cve_id TEXT,
            osv_id TEXT,
            namespace TEXT,
            meta TEXT,
            proj TEXT,
            release TEXT,
            cvss REAL,
            priority TEXT,
            exploitability TEXT,
            PRIMARY KEY (cve_id, namespace, meta, proj, release)
        );

        CREATE TABLE IF NOT EXISTS vuln_package_ranges (
            cve_id TEXT,
            osv_id TEXT,
            namespace TEXT,
            meta TEXT,
            proj TEXT,
            ranges_json TEXT,
            versions_json TEXT,
            cvss REAL,
            priority TEXT,
            exploitability TEXT,
            PRIMARY KEY (cve_id, namespace, meta, proj)
        );
        """
    )
    # Backward-compatible migration for existing local DBs.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(vuln_records)")}
    add_cols = [
        ("title", "TEXT"),
        ("details", "TEXT"),
        ("published", "TEXT"),
        ("modified", "TEXT"),
        ("source", "TEXT"),
    ]
    for col, col_type in add_cols:
        if col not in columns:
            conn.execute(f"ALTER TABLE vuln_records ADD COLUMN {col} {col_type}")


def sample_osv_records() -> List[Dict[str, object]]:
    """Minimal OSS sample coverage for pipeline and UI behavior."""

    return [
        {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Log4Shell remote code execution in log4j-core",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.17.1"}]}],
                    "versions": ["2.12.0", "2.14.1", "2.15.0", "2.16.0"],
                }
            ],
        },
        {
            "id": "GHSA-xr7q-jx4m-x55m",
            "aliases": ["CVE-2022-1471"],
            "summary": "SnakeYAML unsafe deserialization",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.yaml:snakeyaml"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
                    "versions": ["1.29", "1.30", "1.31", "1.33"],
                }
            ],
        },
        {
            "id": "GHSA-ccgv-vj62-xf9h",
            "aliases": ["CVE-2024-38820"],
            "summary": "Spring framework reflected XSS",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.springframework:spring-web"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.40"}]}],
                    "versions": ["5.3.30", "5.3.31", "5.3.39"],
                },
                {
                    "package": {"ecosystem": "Maven", "name": "org.springframework:spring-context"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.40"}]}],
                    "versions": ["5.3.31", "5.3.39"],
                },
            ],
        },
        {
            "id": "GHSA-qppj-fm5r-hxr3",
            "aliases": ["CVE-2022-22965"],
            "summary": "Spring4Shell RCE",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.springframework:spring-beans"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.3.18"}]}],
                    "versions": ["5.3.10", "5.3.15", "5.3.17"],
                }
            ],
        },
        {
            "id": "GHSA-f6jg-3vfj-7p5f",
            "aliases": ["CVE-2023-44487"],
            "summary": "HTTP/2 rapid reset",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "io.netty:netty-codec-http2"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.1.100.Final"}]}],
                    "versions": ["4.1.86.Final", "4.1.94.Final", "4.1.99.Final"],
                }
            ],
        },
        {
            "id": "GHSA-7jwh-3vrq-hh38",
            "aliases": ["CVE-2024-22259"],
            "summary": "Spring Framework path traversal",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.springframework:spring-webmvc"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1.4"}]}],
                    "versions": ["6.1.0", "6.1.2", "6.1.3"],
                }
            ],
        },
        {
            "id": "GHSA-8r3f-844c-mc37",
            "aliases": ["CVE-2023-33201"],
            "summary": "ActiveMQ command injection",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.apache.activemq:activemq-client"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.18.3"}]}],
                    "versions": ["5.15.8", "5.16.6", "5.17.2"],
                }
            ],
        },
        {
            "id": "GHSA-2fc4-44qq-33vq",
            "aliases": ["CVE-2023-2976"],
            "summary": "jose4j signature bypass",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.bitbucket.b_c:jose4j"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.9.3"}]}],
                    "versions": ["0.7.9", "0.8.0", "0.9.2"],
                }
            ],
        },
        {
            "id": "GHSA-3f5j-82c9-rxww",
            "aliases": ["CVE-2024-31449"],
            "summary": "Jackson-databind polymorphic deserialization",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15.4"}]}],
                    "versions": ["2.14.0", "2.14.2", "2.15.3"],
                }
            ],
        },
        {
            "id": "RHEL-2024-0001",
            "aliases": ["CVE-2024-3094"],
            "summary": "xz backdoor sample placeholder",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"}],
            "affected": [
                {
                    "package": {"ecosystem": "RPM", "name": "rhel/xz"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4.6-2"}]}],
                    "versions": ["5.4.3-1", "5.4.4-1", "5.4.5-1"],
                }
            ],
        },
    ]


def clear_existing_data(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM vuln_records")
    conn.execute("DELETE FROM vuln_version_edges")
    conn.execute("DELETE FROM vuln_package_ranges")
    conn.commit()


def normalize_ecosystem_name(value: str) -> str:
    return value.strip().lower().replace("-", "").replace("_", "")


def record_ecosystems(record: Dict[str, object]) -> Set[str]:
    out: Set[str] = set()
    affected = record.get("affected") or []
    if not isinstance(affected, list):
        return out
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package") or {}
        if not isinstance(package, dict):
            continue
        ecosystem = str(package.get("ecosystem", "")).strip()
        if ecosystem:
            out.add(normalize_ecosystem_name(ecosystem))
    return out


def record_matches_ecosystem_filter(record: Dict[str, object], allowed_ecosystems: Optional[Set[str]]) -> bool:
    if not allowed_ecosystems:
        return True
    rec_ecos = record_ecosystems(record)
    if not rec_ecos:
        return False
    return any(e in allowed_ecosystems for e in rec_ecos)


def normalize_package_key(namespace: str, meta: str, proj: str) -> Tuple[str, str, str]:
    return (
        namespace.strip().lower(),
        meta.strip(),
        proj.strip(),
    )


def record_package_keys(record: Dict[str, object]) -> Set[Tuple[str, str, str]]:
    out: Set[Tuple[str, str, str]] = set()
    affected = record.get("affected") or []
    if not isinstance(affected, list):
        return out
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package") or {}
        if not isinstance(package, dict):
            continue
        ecosystem = str(package.get("ecosystem", "")).strip()
        name = str(package.get("name", "")).strip()
        if not ecosystem or not name:
            continue
        namespace, meta, proj = split_coords(ecosystem, name)
        if not proj:
            continue
        out.add(normalize_package_key(namespace, meta, proj))
    return out


def record_matches_package_filter(
    record: Dict[str, object],
    package_allowlist: Optional[Set[Tuple[str, str, str]]],
) -> bool:
    if not package_allowlist:
        return True
    rec_keys = record_package_keys(record)
    if not rec_keys:
        return False
    return any(key in package_allowlist for key in rec_keys)


def load_package_allowlist(path: Optional[Path]) -> Optional[Set[Tuple[str, str, str]]]:
    if not path or not path.exists():
        return None
    out: Set[Tuple[str, str, str]] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 3:
            ns, meta, proj = parts
            if ns and proj:
                out.add(normalize_package_key(ns, meta, proj))
    return out or None


def build_ingest_fingerprint(
    source_zip: Optional[Path],
    source_dir: Path,
    allowed_ecosystems: Set[str],
    package_allowlist_file: Optional[Path],
) -> Dict[str, object]:
    out: Dict[str, object] = {
        "source_dir": str(source_dir),
        "source_zip": str(source_zip) if source_zip else "",
        "allowed_ecosystems": sorted(list(allowed_ecosystems)),
        "package_allowlist_file": str(package_allowlist_file) if package_allowlist_file else "",
        "package_allowlist_sha256": "",
        "source_zip_sha256": "",
    }
    if source_zip and source_zip.exists():
        out["source_zip_sha256"] = file_sha256(source_zip)
        out["source_zip_size"] = source_zip.stat().st_size
    if package_allowlist_file and package_allowlist_file.exists():
        out["package_allowlist_sha256"] = file_sha256(package_allowlist_file)
    return out


def should_skip_ingest(db_path: Path, expected: Dict[str, object]) -> bool:
    meta = read_json_file(metadata_path_for_db(db_path))
    if not meta:
        return False
    previous = meta.get("fingerprint")
    if not isinstance(previous, dict):
        return False
    return previous == expected


def iter_records_from_payload(payload: object) -> Iterator[Dict[str, object]]:
    if isinstance(payload, dict):
        yield payload
        return
    if isinstance(payload, list):
        for row in payload:
            if isinstance(row, dict):
                yield row


def iter_osv_records(
    source_dir: Path,
    source_zip: Optional[Path],
    allowed_ecosystems: Optional[Set[str]],
    package_allowlist: Optional[Set[Tuple[str, str, str]]],
) -> Iterator[Dict[str, object]]:
    yielded = 0
    if source_zip and source_zip.exists():
        with zipfile.ZipFile(source_zip) as zf:
            for name in sorted(zf.namelist()):
                if not name.endswith(".json"):
                    continue
                if name.endswith("/"):
                    continue
                with zf.open(name, "r") as handle:
                    try:
                        payload = json.loads(handle.read().decode("utf-8"))
                    except Exception:
                        continue
                for record in iter_records_from_payload(payload):
                    if record_matches_ecosystem_filter(record, allowed_ecosystems) and record_matches_package_filter(record, package_allowlist):
                        yielded += 1
                        yield record

    if source_dir.exists():
        for path in sorted(source_dir.rglob("*.json")):
            if source_zip and path.resolve() == source_zip.resolve():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for record in iter_records_from_payload(payload):
                if record_matches_ecosystem_filter(record, allowed_ecosystems) and record_matches_package_filter(record, package_allowlist):
                    yielded += 1
                    yield record

    if yielded == 0:
        return


def extract_cvss(record: Dict[str, object]) -> float:
    severity = record.get("severity") or []
    if isinstance(severity, list):
        for item in severity:
            if not isinstance(item, dict):
                continue
            score = item.get("score")
            if isinstance(score, str) and score.startswith("CVSS:"):
                return vector_to_base_score(score)
            if isinstance(score, (int, float)):
                return float(score)

    dbs = record.get("database_specific") or {}
    if isinstance(dbs, dict):
        sev = dbs.get("severity")
        if isinstance(sev, (int, float)):
            return float(sev)

    return 0.0


def iter_edges(record: Dict[str, object], cvss: float) -> Iterable[VulnVersionEdge]:
    aliases = record.get("aliases") or []
    cve_id = next((x for x in aliases if isinstance(x, str) and x.startswith("CVE-")), None)
    if not cve_id:
        rid = str(record.get("id", ""))
        if rid.startswith("CVE-"):
            cve_id = rid
    if not cve_id:
        return []

    osv_id = str(record.get("id", cve_id))
    exploitability = exploitability_from_cvss(cvss)
    priority = priority_from_cvss(cvss)

    edges: List[VulnVersionEdge] = []
    affected = record.get("affected") or []
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package") or {}
        if not isinstance(package, dict):
            continue
        ecosystem = str(package.get("ecosystem", "")).strip() or "generic"
        pkg_name = str(package.get("name", "")).strip()
        if not pkg_name:
            continue
        namespace, meta, proj = split_coords(ecosystem, pkg_name)

        versions = item.get("versions") or []
        if isinstance(versions, list):
            for version in versions:
                if not isinstance(version, str) or not version.strip():
                    continue
                edges.append(
                    VulnVersionEdge(
                        cve_id=cve_id,
                        osv_id=osv_id,
                        namespace=namespace,
                        meta=meta,
                        proj=proj,
                        release=version.strip(),
                        cvss=cvss,
                        exploitability=exploitability,
                        priority=priority,
                    )
                )
    return edges


def ingest_records(
    conn: sqlite3.Connection,
    records: Iterable[Dict[str, object]],
    store_raw_json: bool = False,
    progress_every: int = 5000,
) -> Tuple[int, int]:
    ingested_at = now_iso()
    vuln_count = 0
    edge_count = 0

    for idx, record in enumerate(records, start=1):
        aliases = record.get("aliases") or []
        cve_id = next((x for x in aliases if isinstance(x, str) and x.startswith("CVE-")), None)
        if not cve_id:
            rid = str(record.get("id", ""))
            if rid.startswith("CVE-"):
                cve_id = rid
        if not cve_id:
            continue

        cvss = extract_cvss(record)
        priority = priority_from_cvss(cvss)
        exploitability = exploitability_from_cvss(cvss)
        summary = str(record.get("summary") or record.get("details") or "")
        title = str(record.get("summary") or "")
        details = str(record.get("details") or "")
        published = str(record.get("published") or "")
        modified = str(record.get("modified") or "")
        source = "osv"

        conn.execute(
            """
            INSERT OR REPLACE INTO vuln_records
            (cve_id, osv_id, summary, title, details, published, modified, source, cvss, priority, exploitability, raw_json, ingested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                str(record.get("id", cve_id)),
                summary,
                title,
                details,
                published,
                modified,
                source,
                cvss,
                priority,
                exploitability,
                json.dumps(record, separators=(",", ":")) if store_raw_json else None,
                ingested_at,
            ),
        )
        vuln_count += 1

        for edge in iter_edges(record, cvss):
            conn.execute(
                """
                INSERT OR REPLACE INTO vuln_version_edges
                (cve_id, osv_id, namespace, meta, proj, release, cvss, priority, exploitability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    edge.cve_id,
                    edge.osv_id,
                    edge.namespace,
                    edge.meta,
                    edge.proj,
                    edge.release,
                    edge.cvss,
                    edge.priority,
                    edge.exploitability,
                ),
            )
            edge_count += 1

        affected = record.get("affected") or []
        for item in affected:
            if not isinstance(item, dict):
                continue
            package = item.get("package") or {}
            if not isinstance(package, dict):
                continue
            ecosystem = str(package.get("ecosystem", "")).strip() or "generic"
            pkg_name = str(package.get("name", "")).strip()
            if not pkg_name:
                continue
            namespace, meta, proj = split_coords(ecosystem, pkg_name)
            conn.execute(
                """
                INSERT OR REPLACE INTO vuln_package_ranges
                (cve_id, osv_id, namespace, meta, proj, ranges_json, versions_json, cvss, priority, exploitability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    str(record.get("id", cve_id)),
                    namespace,
                    meta,
                    proj,
                    json.dumps(item.get("ranges") or [], separators=(",", ":")),
                    json.dumps(item.get("versions") or [], separators=(",", ":")),
                    cvss,
                    priority,
                    exploitability,
                ),
            )

        if progress_every > 0 and idx % progress_every == 0:
            conn.commit()
            print(f"...processed {idx} records | kept {vuln_count} CVE records | {edge_count} version edges")

    conn.commit()
    return vuln_count, edge_count


def write_sample_source(dest_dir: Path, force: bool) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    out_path = dest_dir / "sample-osv.json"
    if out_path.exists() and not force:
        return out_path
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(sample_osv_records(), handle, indent=2)
    return out_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--source-zip", type=Path, default=DEFAULT_SOURCE_ZIP, help="Optional OSV all.zip or ecosystem zip")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--write-sample", action="store_true", help="Write built-in sample OSV file before ingest")
    parser.add_argument("--force-sample", action="store_true", help="Overwrite existing sample OSV file")
    parser.add_argument("--allowed-ecosystems", default="", help="Comma-separated ecosystems filter (e.g. Maven,npm,PyPI)")
    parser.add_argument(
        "--package-allowlist-file",
        type=Path,
        default=None,
        help="Optional file of namespace|meta|proj rows; only ingest OSV records for these packages",
    )
    parser.add_argument("--append", action="store_true", help="Append/update records instead of clearing existing tables first")
    parser.add_argument("--force-reingest", action="store_true", help="Ignore ingest fingerprint cache and ingest anyway")
    parser.add_argument("--store-raw-json", action="store_true", help="Store raw OSV JSON payloads in SQLite (larger DB)")
    parser.add_argument("--progress-every", type=int, default=5000, help="Progress log interval in record count")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.db.parent.mkdir(parents=True, exist_ok=True)

    if args.write_sample:
        path = write_sample_source(args.source_dir, force=args.force_sample)
        print(f"Wrote sample OSV source: {path}")

    allowed = {normalize_ecosystem_name(x) for x in str(args.allowed_ecosystems or "").split(",") if x.strip()}
    source_zip = args.source_zip if args.source_zip and args.source_zip.exists() else None
    package_allowlist = load_package_allowlist(args.package_allowlist_file)
    fingerprint = build_ingest_fingerprint(
        source_zip=source_zip,
        source_dir=args.source_dir,
        allowed_ecosystems=allowed,
        package_allowlist_file=args.package_allowlist_file,
    )
    if package_allowlist:
        print(f"Package allowlist loaded: {len(package_allowlist)} package keys from {args.package_allowlist_file}")

    if not args.append and not args.force_reingest and args.db.exists() and should_skip_ingest(args.db, fingerprint):
        print("Ingest inputs unchanged (source + filters + package allowlist); reusing existing vuln DB.")
        print(f"Database: {args.db}")
        return 0

    records = iter_osv_records(
        args.source_dir,
        source_zip=source_zip,
        allowed_ecosystems=allowed or None,
        package_allowlist=package_allowlist,
    )

    conn = sqlite3.connect(args.db)
    try:
        ensure_schema(conn)
        if not args.append:
            clear_existing_data(conn)
        vuln_count, edge_count = ingest_records(
            conn,
            records,
            store_raw_json=bool(args.store_raw_json),
            progress_every=max(0, int(args.progress_every or 0)),
        )
    finally:
        conn.close()

    if vuln_count == 0:
        if args.write_sample:
            print("No records matched filter; using built-in sample OSV dataset.")
            conn2 = sqlite3.connect(args.db)
            try:
                ensure_schema(conn2)
                if not args.append:
                    clear_existing_data(conn2)
                vuln_count, edge_count = ingest_records(conn2, sample_osv_records(), store_raw_json=bool(args.store_raw_json))
            finally:
                conn2.close()
        else:
            print("WARN: No OSV records ingested. Check source-dir/source-zip and ecosystem filter.")

    write_json_file(
        metadata_path_for_db(args.db),
        {
            "updated_at": now_iso(),
            "db_path": str(args.db),
            "vulnerability_count": int(vuln_count),
            "version_edge_count": int(edge_count),
            "fingerprint": fingerprint,
        },
    )

    print(f"Ingested vulnerabilities: {vuln_count}")
    print(f"Ingested version edges: {edge_count}")
    print(f"Database: {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fetch CISA KEV and FIRST EPSS signals for Risk Navigator."""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "vulns.db"
DEFAULT_EXTERNAL_DIR = ROOT / "data" / "external"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_json(url: str, timeout: int = 30) -> Dict[str, object]:
    req = urllib.request.Request(url, headers={"User-Agent": "risk-navigator/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body)


def load_cves_from_db(db_path: Path) -> List[str]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT cve_id FROM vuln_records ORDER BY cve_id").fetchall()
        return [row[0] for row in rows if row and row[0]]
    finally:
        conn.close()


def chunked(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def normalize_kev(payload: Dict[str, object]) -> Dict[str, object]:
    data = {}
    vulns = payload.get("vulnerabilities") or []
    if isinstance(vulns, list):
        for row in vulns:
            if not isinstance(row, dict):
                continue
            cve = row.get("cveID")
            if not isinstance(cve, str):
                continue
            data[cve] = {
                "vendor": row.get("vendorProject", ""),
                "product": row.get("product", ""),
                "vulnerability_name": row.get("vulnerabilityName", ""),
                "date_added": row.get("dateAdded", ""),
                "short_description": row.get("shortDescription", ""),
                "required_action": row.get("requiredAction", ""),
                "due_date": row.get("dueDate", ""),
                "known_ransomware_use": row.get("knownRansomwareCampaignUse", ""),
            }
    return {"fetched_at": now_iso(), "data": data}


def sample_kev() -> Dict[str, object]:
    return {
        "fetched_at": now_iso(),
        "data": {
            "CVE-2021-44228": {
                "vendor": "Apache",
                "product": "Log4j",
                "vulnerability_name": "Log4Shell",
                "date_added": "2021-12-10",
                "short_description": "Remote code execution in log4j",
                "required_action": "Update to a fixed version",
                "due_date": "2021-12-24",
                "known_ransomware_use": "Known",
            },
            "CVE-2022-22965": {
                "vendor": "VMware",
                "product": "Spring Framework",
                "vulnerability_name": "Spring4Shell",
                "date_added": "2022-04-01",
                "short_description": "RCE vulnerability",
                "required_action": "Apply patch",
                "due_date": "2022-04-15",
                "known_ransomware_use": "Unknown",
            },
            "CVE-2023-44487": {
                "vendor": "Multiple",
                "product": "HTTP/2",
                "vulnerability_name": "HTTP/2 rapid reset",
                "date_added": "2023-10-10",
                "short_description": "DoS via rapid stream cancellation",
                "required_action": "Patch upstream components",
                "due_date": "2023-10-31",
                "known_ransomware_use": "Unknown",
            },
            "CVE-2024-3094": {
                "vendor": "XZ Utils",
                "product": "liblzma",
                "vulnerability_name": "XZ backdoor",
                "date_added": "2024-03-29",
                "short_description": "Supply-chain compromise",
                "required_action": "Use clean package versions",
                "due_date": "2024-04-19",
                "known_ransomware_use": "Unknown",
            },
        },
    }


def fetch_epss(cves: Sequence[str], batch_size: int = 100, sleep_ms: int = 200) -> Dict[str, object]:
    data: Dict[str, Dict[str, object]] = {}
    today = datetime.now(timezone.utc).date().isoformat()

    for batch in chunked(list(cves), batch_size):
        if not batch:
            continue
        params = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{EPSS_URL}?{params}"
        payload = fetch_json(url)
        rows = payload.get("data") or []
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                cve = row.get("cve")
                if not isinstance(cve, str):
                    continue
                try:
                    epss_val = float(row.get("epss", 0.0) or 0.0)
                except (TypeError, ValueError):
                    epss_val = 0.0
                try:
                    pct = float(row.get("percentile", 0.0) or 0.0)
                except (TypeError, ValueError):
                    pct = 0.0
                data[cve] = {
                    "epss": round(epss_val, 6),
                    "percentile": round(pct, 6),
                    "date": str(row.get("date") or today),
                }
        time.sleep(max(0, sleep_ms) / 1000.0)

    return {"fetched_at": now_iso(), "data": data}


def sample_epss(cves: Sequence[str]) -> Dict[str, object]:
    defaults = {
        "CVE-2021-44228": (0.972, 0.998),
        "CVE-2022-1471": (0.782, 0.965),
        "CVE-2022-22965": (0.745, 0.941),
        "CVE-2023-44487": (0.901, 0.989),
        "CVE-2024-3094": (0.998, 0.999),
    }
    today = datetime.now(timezone.utc).date().isoformat()
    data = {}
    for cve in cves:
        epss, pct = defaults.get(cve, (0.211, 0.532))
        data[cve] = {"epss": epss, "percentile": pct, "date": today}
    return {"fetched_at": now_iso(), "data": data}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--external-dir", type=Path, default=DEFAULT_EXTERNAL_DIR)
    parser.add_argument("--cve-file", type=Path, help="Optional JSON list of CVE IDs")
    parser.add_argument("--sample-only", action="store_true", help="Use built-in sample KEV/EPSS instead of network")
    parser.add_argument("--batch-size", type=int, default=100)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.external_dir.mkdir(parents=True, exist_ok=True)

    cves: List[str] = []
    if args.cve_file and args.cve_file.exists():
        with open(args.cve_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, list):
            cves = [str(x) for x in payload if isinstance(x, str) and x.startswith("CVE-")]

    if not cves:
        cves = load_cves_from_db(args.db)

    if args.sample_only:
        kev = sample_kev()
        epss = sample_epss(cves)
    else:
        try:
            kev_payload = fetch_json(KEV_URL)
            kev = normalize_kev(kev_payload)
        except Exception as exc:
            print(f"WARN: KEV fetch failed ({exc}); using sample KEV")
            kev = sample_kev()

        try:
            epss = fetch_epss(cves, batch_size=args.batch_size)
        except Exception as exc:
            print(f"WARN: EPSS fetch failed ({exc}); using sample EPSS")
            epss = sample_epss(cves)

    kev_path = args.external_dir / "kev.json"
    epss_path = args.external_dir / "epss.json"

    with open(kev_path, "w", encoding="utf-8") as handle:
        json.dump(kev, handle, indent=2)

    with open(epss_path, "w", encoding="utf-8") as handle:
        json.dump(epss, handle, indent=2)

    print(f"Wrote {kev_path} ({len(kev.get('data', {}))} CVEs)")
    print(f"Wrote {epss_path} ({len(epss.get('data', {}))} CVEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

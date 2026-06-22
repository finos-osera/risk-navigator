#!/usr/bin/env python3
"""Download official OSV vulnerability dumps for local ingestion."""

from __future__ import annotations

import argparse
import json
import shutil
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities/all.zip"
DEFAULT_DEST = ROOT / "data" / "local" / "osv" / "all.zip"
USER_AGENT = "risk-navigator/0.1"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def metadata_path(dest: Path) -> Path:
    return dest.with_suffix(dest.suffix + ".meta.json")


def load_metadata(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def save_metadata(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def extract_headers(resp_headers: object) -> Dict[str, object]:
    etag = ""
    last_modified = ""
    content_length = 0
    try:
        etag = str(resp_headers.get("ETag", "") or "")
        last_modified = str(resp_headers.get("Last-Modified", "") or "")
        cl_raw = str(resp_headers.get("Content-Length", "") or "")
        content_length = int(cl_raw) if cl_raw.isdigit() else 0
    except Exception:
        pass
    return {
        "etag": etag,
        "last_modified": last_modified,
        "content_length": content_length,
    }


def remote_head(url: str, timeout: int) -> Dict[str, object]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        info = extract_headers(resp.headers)
    info["checked_at"] = now_iso()
    return info


def download(url: str, dest: Path, timeout: int, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method="GET")
    tmp = dest.with_suffix(dest.suffix + ".part")
    if tmp.exists():
        tmp.unlink()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        info = extract_headers(resp.headers)
        with open(tmp, "wb") as handle:
            shutil.copyfileobj(resp, handle, length=1024 * 1024)
    tmp.replace(dest)
    info["downloaded_at"] = now_iso()
    return info


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_OSV_URL)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--force", action="store_true", help="Re-download even if destination already exists")
    parser.add_argument("--timeout", type=int, default=120)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.dest.parent.mkdir(parents=True, exist_ok=True)
    meta_path = metadata_path(args.dest)
    meta = load_metadata(meta_path)

    if args.force or not args.dest.exists():
        info = download(args.url, args.dest, timeout=max(10, int(args.timeout)))
        save_metadata(
            meta_path,
            {
                "url": args.url,
                "etag": info.get("etag", ""),
                "last_modified": info.get("last_modified", ""),
                "content_length": info.get("content_length", 0),
                "fetched_at": info.get("downloaded_at", now_iso()),
            },
        )
        print(f"Downloaded OSV dump: {args.dest}")
        return 0

    remote = {}
    try:
        remote = remote_head(args.url, timeout=max(10, int(args.timeout)))
    except Exception as exc:
        print(f"WARN: Could not check upstream OSV metadata ({exc}); using local copy: {args.dest}")
        return 0

    remote_etag = str(remote.get("etag") or "")
    remote_last_mod = str(remote.get("last_modified") or "")
    remote_len = int(remote.get("content_length") or 0)
    local_len = args.dest.stat().st_size if args.dest.exists() else 0
    local_etag = str(meta.get("etag") or "")
    local_last_mod = str(meta.get("last_modified") or "")

    if remote_etag and local_etag and remote_etag == local_etag:
        print(f"OSV dump unchanged (ETag match). Using local copy: {args.dest}")
        save_metadata(meta_path, {**meta, "url": args.url, "checked_at": now_iso()})
        return 0

    if remote_last_mod and local_last_mod and remote_last_mod == local_last_mod:
        print(f"OSV dump unchanged (Last-Modified match). Using local copy: {args.dest}")
        save_metadata(meta_path, {**meta, "url": args.url, "checked_at": now_iso()})
        return 0

    if (not local_etag and not local_last_mod) and remote_len > 0 and local_len == remote_len:
        print(f"OSV dump appears unchanged (content-length match). Using local copy: {args.dest}")
        save_metadata(
            meta_path,
            {
                "url": args.url,
                "etag": remote_etag,
                "last_modified": remote_last_mod,
                "content_length": remote_len,
                "checked_at": now_iso(),
            },
        )
        return 0

    info = download(args.url, args.dest, timeout=max(10, int(args.timeout)))
    save_metadata(
        meta_path,
        {
            "url": args.url,
            "etag": info.get("etag", ""),
            "last_modified": info.get("last_modified", ""),
            "content_length": info.get("content_length", 0),
            "fetched_at": info.get("downloaded_at", now_iso()),
        },
    )
    print(f"Downloaded updated OSV dump: {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build package allowlist from scope dependency edges for targeted OSV ingest."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_ROOT = ROOT / "data" / "raw"
DEFAULT_OUT_DIR = ROOT / "data" / "local" / "allowlists"


def parse_library_id(library_id: str) -> Tuple[str, str, str, str]:
    parts = library_id.split("|", 3)
    if len(parts) != 4:
        return ("", "", "", "")
    return parts[0], parts[1], parts[2], parts[3]


def read_dep_edges(path: Path) -> Set[Tuple[str, str, str]]:
    out: Set[Tuple[str, str, str]] = set()
    if not path.exists():
        return out
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            lid = str(row.get("library_id") or "")
            ns, meta, proj, _ = parse_library_id(lid)
            if ns and proj:
                out.add((ns.strip().lower(), meta.strip(), proj.strip()))
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--out-file", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dep_path = args.raw_root / args.scope / "02-dep-edges.csv"
    keys = sorted(read_dep_edges(dep_path))
    if args.out_file:
        out_file = args.out_file
    else:
        out_file = args.out_dir / f"{args.scope}-packages.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as handle:
        handle.write("# namespace|meta|proj\n")
        for ns, meta, proj in keys:
            handle.write(f"{ns}|{meta}|{proj}\n")
    print(f"Wrote allowlist: {out_file}")
    print(f"Package keys: {len(keys)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


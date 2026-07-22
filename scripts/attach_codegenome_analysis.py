#!/usr/bin/env python3
"""Attach Codegenome compatibility analyses to a built Risk Navigator dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ANALYSIS_DIR = ROOT / "data" / "codegenome"


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def json_text(payload: object, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"
    return json.dumps(payload, separators=(",", ":"), sort_keys=False) + "\n"


def write_json(path: Path, payload: object, pretty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_text(payload, pretty=pretty), encoding="utf-8")


def analysis_rows(payload: object) -> List[Dict[str, object]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("analyses") or payload.get("codegenome_analyses") or payload.get("data") or []
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def library_key_from_row(row: Dict[str, object]) -> Tuple[str, str, str, str]:
    library_id = str(row.get("library_id") or row.get("id") or "").strip()
    if library_id.count("|") == 3:
        namespace, meta, proj, release = library_id.split("|", 3)
        return namespace, meta, proj, release
    return (
        str(row.get("namespace") or "").strip(),
        str(row.get("meta") or row.get("group") or "").strip(),
        str(row.get("proj") or row.get("name") or row.get("artifact") or "").strip(),
        str(row.get("release") or row.get("current_release") or "").strip(),
    )


def normalize_analysis(row: Dict[str, object], matched_library_id: str) -> Dict[str, object]:
    summary = row.get("summary") if isinstance(row.get("summary"), dict) else {}
    details = {
        "removed_public_symbols": row.get("removed_public_symbols", []),
        "added_public_symbols": row.get("added_public_symbols", []),
        "moved_public_symbols": row.get("moved_public_symbols", []),
        "changed_public_symbols": row.get("changed_public_symbols", []),
        "consumer_usage_impacts": row.get("consumer_usage_impacts", []),
        "high_complexity_changed_symbols": row.get("high_complexity_changed_symbols", []),
        "removed_imports": row.get("removed_imports", []),
        "added_imports": row.get("added_imports", []),
    }
    compact_details = {key: value for key, value in details.items() if value}
    return {
        "analysis_id": str(row.get("analysis_id") or row.get("id") or f"{matched_library_id}|codegenome").strip(),
        "library_id": matched_library_id,
        "package": str(row.get("package") or row.get("package_id") or "").strip(),
        "current_release": str(row.get("current_release") or row.get("release") or "").strip(),
        "candidate_release": str(row.get("candidate_release") or row.get("target_release") or "").strip(),
        "distance_to_safe": str(row.get("distance_to_safe") or "").strip(),
        "classification": str(row.get("classification") or "UNKNOWN").strip(),
        "classification_reasons": [
            str(item)
            for item in row.get("classification_reasons", [])
            if str(item).strip()
        ]
        if isinstance(row.get("classification_reasons"), list)
        else [],
        "cves": [str(item) for item in row.get("cves", []) if str(item).strip()] if isinstance(row.get("cves"), list) else [],
        "summary": {
            "removed_public_symbols": int(summary.get("removed_public_symbols") or 0),
            "added_public_symbols": int(summary.get("added_public_symbols") or 0),
            "moved_public_symbols": int(summary.get("moved_public_symbols") or 0),
            "changed_public_symbols": int(summary.get("changed_public_symbols") or 0),
            "consumer_usage_impacts": int(summary.get("consumer_usage_impacts") or 0),
            "high_complexity_changed_symbols": int(summary.get("high_complexity_changed_symbols") or 0),
            "new_circular_dependency_count": int(summary.get("new_circular_dependency_count") or 0),
            "removed_imports": int(summary.get("removed_imports") or 0),
            "added_imports": int(summary.get("added_imports") or 0),
        },
        "details": compact_details,
        "generated_at": str(row.get("generated_at") or "").strip(),
        "source": str(row.get("source") or "codegenome").strip(),
    }


def attach(dataset: Dict[str, object], rows: Sequence[Dict[str, object]]) -> Dict[str, int]:
    libraries = dataset.get("libraries")
    if not isinstance(libraries, list):
        raise ValueError("dataset.libraries must be a list")

    by_id = {str(lib.get("id") or ""): lib for lib in libraries if isinstance(lib, dict)}
    by_tuple = {}
    for lib in libraries:
        if not isinstance(lib, dict):
            continue
        key = (
            str(lib.get("namespace") or "").strip(),
            str(lib.get("meta") or "").strip(),
            str(lib.get("proj") or "").strip(),
            str(lib.get("release") or "").strip(),
        )
        by_tuple[key] = lib

    matched = 0
    unmatched = 0
    for row in rows:
        key = library_key_from_row(row)
        library_id = str(row.get("library_id") or row.get("id") or "").strip()
        lib = by_id.get(library_id) if library_id else None
        if lib is None:
            lib = by_tuple.get(key)
        if lib is None:
            unmatched += 1
            continue
        analyses = lib.setdefault("codegenome_analyses", [])
        if not isinstance(analyses, list):
            analyses = []
            lib["codegenome_analyses"] = analyses
        normalized = normalize_analysis(row, str(lib.get("id") or library_id))
        existing_ids = {str(item.get("analysis_id") or "") for item in analyses if isinstance(item, dict)}
        if normalized["analysis_id"] in existing_ids:
            analyses[:] = [
                normalized if isinstance(item, dict) and str(item.get("analysis_id") or "") == normalized["analysis_id"] else item
                for item in analyses
            ]
        else:
            analyses.append(normalized)
        matched += 1

    meta = dataset.setdefault("meta", {})
    if isinstance(meta, dict):
        external = meta.setdefault("external_signals", {})
        if isinstance(external, dict):
            external["codegenome_analysis"] = {
                "enabled": bool(matched),
                "attached_libraries": sum(
                    1
                    for lib in libraries
                    if isinstance(lib, dict) and isinstance(lib.get("codegenome_analyses"), list) and lib.get("codegenome_analyses")
                ),
                "analysis_count": sum(
                    len(lib.get("codegenome_analyses", []))
                    for lib in libraries
                    if isinstance(lib, dict) and isinstance(lib.get("codegenome_analyses"), list)
                ),
                "unmatched_analysis_count": unmatched,
            }
    return {"matched": matched, "unmatched": unmatched}


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Built data/<scope>.json dataset")
    parser.add_argument("--analysis", type=Path, help="Sidecar analysis JSON; defaults to data/codegenome/<scope>.json")
    parser.add_argument("--output", type=Path, help="Output path; defaults to stdout unless --in-place is used")
    parser.add_argument("--in-place", action="store_true", help="Rewrite dataset in place")
    parser.add_argument("--allow-missing", action="store_true", help="No-op when the analysis sidecar does not exist")
    parser.add_argument("--pretty", action="store_true", help="Write formatted JSON instead of compact dataset JSON")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    dataset_path = args.dataset
    analysis_path = args.analysis or (DEFAULT_ANALYSIS_DIR / dataset_path.name)
    if not analysis_path.exists():
        if args.allow_missing:
            print(f"No Codegenome sidecar found at {analysis_path}; leaving dataset unchanged.")
            return 0
        raise FileNotFoundError(analysis_path)

    dataset = read_json(dataset_path)
    if not isinstance(dataset, dict):
        raise ValueError("dataset root must be an object")
    rows = analysis_rows(read_json(analysis_path))
    stats = attach(dataset, rows)

    output = dataset_path if args.in_place else args.output
    if output:
        write_json(output, dataset, pretty=args.pretty)
    else:
        print(json_text(dataset, pretty=args.pretty), end="")
    print(f"Attached {stats['matched']} Codegenome analysis row(s); unmatched={stats['unmatched']}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

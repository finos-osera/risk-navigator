#!/usr/bin/env python3
"""Deterministically migrate legacy package/library identities across raw CSVs and JSON datasets to canonical PURLs."""

from __future__ import annotations

import argparse
import copy
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from purl_identity import (
    canonical_library_id,
     canonical_package_id,
    make_library_id,
    make_package_id,
    parse_library_id,
    parse_package_id,
    parse_purl_spec,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET_FILES = (
    "finos-sample-platform.json",
    "finos-sbom-demo.json",
    "finos-deep-sbom-demo.json",
    "finos-github-org.json",
)


def migrate_versioned_id(raw_id: str) -> str:
    value = str(raw_id or "").strip()
    if not value:
        return ""
    parsed = parse_purl_spec(value, require_version=True)
    if parsed.valid:
        return parsed.canonical_purl
    ns, meta, proj, release = parse_library_id(value)
    if ns and proj and release:
        return make_library_id(ns, meta, proj, release)
    # Handle legacy colon-separated artifact IDs in readiness fixtures/Embedded records (e.g. maven:group:artifact:version)
    colon_parts = value.split(":")
    if len(colon_parts) == 4 and colon_parts[0].lower() == "maven":
        return make_library_id("maven", colon_parts[1], colon_parts[2], colon_parts[3])
    raise ValueError(f"Cannot migrate versioned package identity: {raw_id!r}")


def migrate_package_only_id(raw_id: str) -> str:
    value = str(raw_id or "").strip()
    if not value:
        return ""
    parsed = parse_purl_spec(value, require_version=False)
    if parsed.valid and not parsed.version:
        return parsed.package_purl
    ns, meta, proj = parse_package_id(value)
    if ns and proj:
        return make_package_id(ns, meta, proj)
    raise ValueError(f"Cannot migrate package-only identity: {raw_id!r}")


def _migrate_readiness_eval(eval_obj: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(eval_obj)
    if out.get("artifact_id"):
        out["artifact_id"] = migrate_versioned_id(str(out["artifact_id"]))
    if isinstance(out.get("proposed_closure_artifacts"), list):
        out["proposed_closure_artifacts"] = [
            migrate_versioned_id(str(x)) for x in out["proposed_closure_artifacts"]
        ]
    stages = out.get("stages")
    if isinstance(stages, dict):
        promo = stages.get("artifact_promotion")
        if isinstance(promo, dict) and isinstance(promo.get("artifact_chains"), list):
            for chain_entry in promo["artifact_chains"]:
                if isinstance(chain_entry, dict) and chain_entry.get("artifact_id"):
                    chain_entry["artifact_id"] = migrate_versioned_id(str(chain_entry["artifact_id"]))
    if isinstance(out.get("blockers"), list):
        for blocker in out["blockers"]:
            if not isinstance(blocker, dict):
                continue
            code = str(blocker.get("code") or "")
            for prefix in ("BROKEN_REQUIRED_CHAIN:", "MISSING_REQUIRED_CHAIN:"):
                if code.startswith(prefix):
                    suffix = code[len(prefix) :]
                    blocker["code"] = f"{prefix}{migrate_versioned_id(suffix)}"
    if isinstance(out.get("unrelated_artifact_notices"), list):
        for notice in out["unrelated_artifact_notices"]:
            if isinstance(notice, dict) and notice.get("artifact_id"):
                notice["artifact_id"] = migrate_versioned_id(str(notice["artifact_id"]))
    return out


def dataset_golden_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    libraries = payload.get("libraries") or []
    projects = payload.get("consumer_projects") or []
    amplifiers = payload.get("amplifier_clusters") or []
    inv = payload.get("dependency_inventory") or {}
    return {
        "counts": copy.deepcopy((payload.get("meta") or {}).get("counts")),
        "project_count": len(projects),
        "project_ids": [p.get("id") for p in projects if isinstance(p, dict)],
        "library_count": len(libraries),
        "total_cve_refs": sum(len(lib.get("cves") or []) for lib in libraries if isinstance(lib, dict)),
        "amplifier_cluster_count": len(amplifiers),
        "version_chain_count": len(payload.get("version_chains") or {}),
        "inventory_library_count": len(inv.get("libraries") or []),
        "inventory_project_count": len(inv.get("projects") or []),
        "inventory_edge_count": len(inv.get("edges") or []),
    }


def migrate_dataset_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    before_summary = dataset_golden_summary(payload)
    out = copy.deepcopy(payload)

    id_map: Dict[str, str] = {}
    for lib in out.get("libraries", []) or []:
        if not isinstance(lib, dict):
            continue
        old_id = str(lib.get("id") or "")
        ns = str(lib.get("namespace") or "").strip().lower()
        meta = str(lib.get("meta") or "").strip()
        proj = str(lib.get("proj") or "").strip()
        release = str(lib.get("release") or "").strip()
        new_id = make_library_id(ns, meta, proj, release) if (ns and proj and release) else migrate_versioned_id(old_id)
        if old_id:
            id_map[old_id] = new_id
        lib["id"] = new_id
        if "purl" in lib:
            lib["purl"] = new_id
        if "package_purl" in lib:
            lib["package_purl"] = make_package_id(ns, meta, proj)
        if lib.get("version_chain_ref"):
            lib["version_chain_ref"] = migrate_package_only_id(str(lib["version_chain_ref"]))
        if isinstance(lib.get("patch_readiness"), dict):
            lib["patch_readiness"] = _migrate_readiness_eval(lib["patch_readiness"])
        if isinstance(lib.get("patch_readiness_scenarios"), dict):
            lib["patch_readiness_scenarios"] = {
                k: _migrate_readiness_eval(v) if isinstance(v, dict) else v
                for k, v in lib["patch_readiness_scenarios"].items()
            }

    for proj in out.get("consumer_projects", []) or []:
        if not isinstance(proj, dict):
            continue
        # Never rewrite non-package consumer_projects[*].id
        if isinstance(proj.get("vulnerable_library_ids"), list):
            proj["vulnerable_library_ids"] = [
                id_map.get(str(lid), migrate_versioned_id(str(lid)))
                for lid in proj["vulnerable_library_ids"]
            ]

    for cluster in out.get("amplifier_clusters", []) or []:
        if not isinstance(cluster, dict):
            continue
        if cluster.get("amplifier_id"):
            cluster["amplifier_id"] = migrate_package_only_id(str(cluster["amplifier_id"]))
        if isinstance(cluster.get("amplified_libraries"), list):
            cluster["amplified_libraries"] = [
                id_map.get(str(lid), migrate_versioned_id(str(lid)))
                for lid in cluster["amplified_libraries"]
            ]

    if isinstance(out.get("version_chains"), dict):
        migrated_chains: Dict[str, Any] = {}
        for old_key, chain in out["version_chains"].items():
            new_key = migrate_package_only_id(str(old_key))
            if new_key in migrated_chains and migrated_chains[new_key] != chain:
                raise ValueError(f"Inconsistent version_chains during migration for {new_key}")
            migrated_chains[new_key] = chain
        out["version_chains"] = migrated_chains

    inv = out.get("dependency_inventory")
    if isinstance(inv, dict) and isinstance(inv.get("libraries"), list):
        old_libs: List[str] = [str(x) for x in inv["libraries"]]
        migrated_by_old_index = [migrate_versioned_id(x) for x in old_libs]
        new_libs = sorted(set(migrated_by_old_index))
        new_index_by_id = {val: idx for idx, val in enumerate(new_libs)}
        inv["libraries"] = new_libs
        if isinstance(inv.get("edges"), list):
            cols = inv.get("edge_columns") or ["project", "library", "direct", "qualifier", "parent"]
            lib_col = cols.index("library") if "library" in cols else 1
            parent_col = cols.index("parent") if "parent" in cols else 4
            remapped_edges = []
            for edge in inv["edges"]:
                row = list(edge)
                old_lib_idx = row[lib_col]
                row[lib_col] = new_index_by_id[migrated_by_old_index[old_lib_idx]]
                old_parent_idx = row[parent_col]
                if old_parent_idx is not None:
                    row[parent_col] = new_index_by_id[migrated_by_old_index[old_parent_idx]]
                remapped_edges.append(tuple(row))
            inv["edges"] = [list(e) for e in sorted(set(remapped_edges), key=str)]

    after_summary = dataset_golden_summary(out)
    if before_summary != after_summary:
        raise ValueError(f"Golden summary mismatch after dataset migration: {before_summary} != {after_summary}")
    return out


def migrate_csv_file(path: Path, write: bool = False) -> bool:
    name = path.name
    if name == "01-consumer-projects.csv":
        return False

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    changed = False
    for row in rows:
        if name == "02-dep-edges.csv":
            for col in ("library_id", "parent_id"):
                val = str(row.get(col) or "").strip()
                if val:
                    new_val = migrate_versioned_id(val)
                    if new_val != val:
                        row[col] = new_val
                        changed = True
        elif name in ("03-cve-libs.csv", "04-version-chain.csv"):
            col = "library_id" if "library_id" in fieldnames else ("vulnerable_lib_id" if "vulnerable_lib_id" in fieldnames else "id")
            val = str(row.get(col) or "").strip()
            ns = str(row.get("namespace") or "").strip().lower()
            meta = str(row.get("meta") or "").strip()
            proj = str(row.get("proj") or "").strip()
            rel = str(row.get("release") or "").strip()
            new_val = make_library_id(ns, meta, proj, rel) if (ns and proj and rel) else migrate_versioned_id(val)
            if new_val != val and col in fieldnames:
                row[col] = new_val
                changed = True
        elif name == "05-amplifiers.csv":
            for col in ("cve_lib_id", "amplifier_id", "vulnerable_lib_id"):
                if col not in fieldnames:
                    continue
                val = str(row.get(col) or "").strip()
                if val:
                    new_val = migrate_versioned_id(val)
                    if new_val != val:
                        row[col] = new_val
                        changed = True
        elif name == "06-cve-edges.csv":
            val = str(row.get("library_id") or "").strip()
            if val:
                new_val = migrate_versioned_id(val)
                if new_val != val:
                    row["library_id"] = new_val
                    changed = True

    if changed and write:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    return changed


def migrate_all(root: Path = ROOT, write: bool = False) -> Tuple[List[Path], List[Path]]:
    changed_csvs: List[Path] = []
    changed_datasets: List[Path] = []

    raw_root = root / "data" / "raw"
    if raw_root.exists():
        for csv_path in sorted(raw_root.glob("*/*.csv")):
            if migrate_csv_file(csv_path, write=write):
                changed_csvs.append(csv_path)

    data_dir = root / "data"
    for filename in DATASET_FILES:
        dataset_path = data_dir / filename
        if not dataset_path.exists():
            continue
        raw_text = dataset_path.read_text(encoding="utf-8")
        payload = json.loads(raw_text)
        migrated = migrate_dataset_payload(payload)
        if filename == "finos-github-org.json":
            new_text = json.dumps(migrated, separators=(",", ":")) + "\n"
        else:
            new_text = json.dumps(migrated, indent=2) + "\n"
        if new_text != raw_text:
            changed_datasets.append(dataset_path)
            if write:
                dataset_path.write_text(new_text, encoding="utf-8")

    return changed_csvs, changed_datasets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--write", action="store_true", help="Write migrated files in place")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if any file requires migration")
    args = parser.parse_args()

    changed_csvs, changed_datasets = migrate_all(args.root, write=args.write)
    print(f"CSV files {'updated' if args.write else 'needing migration'}: {len(changed_csvs)}")
    print(f"Dataset JSON files {'updated' if args.write else 'needing migration'}: {len(changed_datasets)}")
    if args.check and (changed_csvs or changed_datasets):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

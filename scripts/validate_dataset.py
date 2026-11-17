#!/usr/bin/env python3
"""Validate that scope JSON matches required Risk Navigator schema fields."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Sequence

from purl_identity import parse_purl_spec

REQUIRED_TOP = ["meta", "departments", "consumer_projects", "libraries", "amplifier_clusters"]
REQUIRED_META = ["scope_type", "scope_name", "extracted_at", "filters_applied", "external_signals", "counts"]
REQUIRED_LIBRARY = [
    "id",
    "namespace",
    "meta",
    "proj",
    "release",
    "max_cvss",
    "cve_count",
    "cves",
    "is_kev_listed",
    "epss_max",
    "consumer_project_ids",
    "direct_consumer_project_ids",
    "direct_consumer_count",
    "transitive_consumer_count",
    "total_consumer_count",
    "version_chain",
    "nearest_safe_version",
    "max_safe_patch_same_minor",
    "distance_to_safe",
    "effort_class",
]


def require_keys(obj: Dict[str, object], keys: Sequence[str], path: str, errors: List[str]) -> None:
    for key in keys:
        if key not in obj:
            errors.append(f"Missing key: {path}.{key}")


def validate(path: Path) -> List[str]:
    errors: List[str] = []
    payload = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(payload, dict):
        return ["Dataset root must be an object"]

    require_keys(payload, REQUIRED_TOP, "$", errors)

    meta = payload.get("meta")
    if isinstance(meta, dict):
        require_keys(meta, REQUIRED_META, "$.meta", errors)
    else:
        errors.append("$.meta must be an object")

    libraries = payload.get("libraries")
    library_ids = set()
    if not isinstance(libraries, list):
        errors.append("$.libraries must be an array")
    else:
        for idx, lib in enumerate(libraries):
            if not isinstance(lib, dict):
                errors.append(f"$.libraries[{idx}] must be an object")
                continue
            require_keys(lib, REQUIRED_LIBRARY, f"$.libraries[{idx}]", errors)
            lid = str(lib.get("id") or "")
            parsed_lid = parse_purl_spec(lid, require_version=True)
            if not parsed_lid.valid:
                errors.append(f"$.libraries[{idx}].id must be a valid versioned PURL: {lid!r} ({parsed_lid.error})")
            else:
                library_ids.add(lid)
            ref = lib.get("version_chain_ref")
            if ref:
                parsed_ref = parse_purl_spec(str(ref), require_version=False)
                if not parsed_ref.valid or parsed_ref.version:
                    errors.append(f"$.libraries[{idx}].version_chain_ref must be a versionless package PURL: {ref!r}")
                if not isinstance(payload.get("version_chains", {}).get(ref), list):
                    errors.append(f"Missing shared version chain: {ref}")

    consumer_projects = payload.get("consumer_projects")
    if isinstance(consumer_projects, list) and library_ids:
        for idx, proj in enumerate(consumer_projects):
            if not isinstance(proj, dict):
                continue
            for v_id in proj.get("vulnerable_library_ids", []) or []:
                if v_id not in library_ids:
                    errors.append(
                        f"$.consumer_projects[{idx}].vulnerable_library_ids contains unknown library PURL: {v_id!r}"
                    )

    amplifier_clusters = payload.get("amplifier_clusters")
    if isinstance(amplifier_clusters, list):
        for idx, cluster in enumerate(amplifier_clusters):
            if not isinstance(cluster, dict):
                continue
            amp_id = str(cluster.get("amplifier_id") or "")
            parsed_amp = parse_purl_spec(amp_id, require_version=False)
            if not parsed_amp.valid or parsed_amp.version:
                errors.append(
                    f"$.amplifier_clusters[{idx}].amplifier_id must be a valid versionless package PURL: {amp_id!r}"
                )
            for amp_lib in cluster.get("amplified_libraries", []) or []:
                if library_ids and amp_lib not in library_ids:
                    errors.append(
                        f"$.amplifier_clusters[{idx}].amplified_libraries contains unknown library PURL: {amp_lib!r}"
                    )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    args = parser.parse_args()

    errors = validate(args.dataset)
    if errors:
        for err in errors:
            print(f"ERROR: {err}")
        return 1
    print("Dataset schema validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

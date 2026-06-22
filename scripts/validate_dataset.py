#!/usr/bin/env python3
"""Validate that scope JSON matches required Risk Navigator schema fields."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Sequence

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
    if not isinstance(libraries, list):
        errors.append("$.libraries must be an array")
    else:
        for idx, lib in enumerate(libraries):
            if not isinstance(lib, dict):
                errors.append(f"$.libraries[{idx}] must be an object")
                continue
            require_keys(lib, REQUIRED_LIBRARY, f"$.libraries[{idx}]", errors)

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

#!/usr/bin/env python3
"""Reference scorer for OSS library risk records."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List


DIMENSION_WEIGHTS = {
    "project_vitality": 0.25,
    "security_health": 0.25,
    "sustainability_governance": 0.20,
    "dependency_hygiene": 0.15,
    "ecosystem_resilience": 0.15,
}


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_value(record: Dict[str, Any], key: str) -> float:
    return float(record.get("scores", {}).get(key, 0.0) or 0.0)


def calculate_oss_vitality(record: Dict[str, Any]) -> float:
    total = 0.0
    for key, weight in DIMENSION_WEIGHTS.items():
        total += clamp(score_value(record, key)) * weight
    return round(clamp(total), 1)


def exposure_factor(enterprise: Dict[str, Any]) -> float:
    app_count = int(enterprise.get("application_count") or 0)
    direct_count = int(enterprise.get("direct_dependency_count") or 0)
    tier1_count = int(enterprise.get("tier1_application_count") or 0)
    internet_count = int(enterprise.get("internet_facing_application_count") or 0)
    regulated_count = int(enterprise.get("regulated_application_count") or 0)

    base = min(1.0, math.log1p(app_count) / math.log(1001))
    direct = min(0.25, direct_count / max(app_count, 1) * 0.25)
    business = min(0.35, (tier1_count * 0.08) + (internet_count * 0.03) + (regulated_count * 0.04))
    return 0.5 + min(0.5, base * 0.35 + direct + business)


def version_risk_factor(enterprise: Dict[str, Any]) -> float:
    versions = max(1, len(enterprise.get("versions_in_use") or []))
    unsupported = int(enterprise.get("unsupported_version_count") or 0)
    vulnerable = int(enterprise.get("known_vulnerable_version_count") or 0)
    return 0.75 + min(0.45, (unsupported / versions * 0.2) + (vulnerable / versions * 0.25))


def calculate_undermaintenance_pressure(record: Dict[str, Any]) -> float:
    evidence = record.get("evidence", {})
    registry = evidence.get("package_registry", {}) if isinstance(evidence, dict) else {}
    github = evidence.get("github", {}) if isinstance(evidence, dict) else {}
    enterprise = record.get("enterprise", {})

    dependents = float(registry.get("dependents") or registry.get("dependent_count") or 0)
    downloads = float(registry.get("monthly_downloads") or registry.get("npm_monthly_downloads") or 0)
    active_maintainers = float(github.get("active_maintainers") or github.get("active_contributors_365d") or 0)
    recent_contributors = float(github.get("recent_contributors_90d") or github.get("active_contributors_90d") or 0)
    enterprise_apps = float(enterprise.get("application_count") or 0)

    downstream_weight = dependents + math.sqrt(downloads) + (enterprise_apps * 10)
    capacity = active_maintainers + recent_contributors
    if downstream_weight <= 0:
        return 0.0
    return round(math.log1p(downstream_weight) / math.log(2 + max(capacity, 0)), 2)


def calculate_enterprise_priority(record: Dict[str, Any], vitality: float) -> float:
    scores = record.get("scores", {})
    enterprise = record.get("enterprise", {})
    criticality = clamp(float(scores.get("ecosystem_criticality", 0.0) or 0.0)) / 100
    confidence = float(scores.get("confidence", 0.7) or 0.7)
    confidence_factor = 0.85 + min(0.15, max(0.0, confidence) * 0.15)

    raw = (
        (100 - vitality)
        * (0.65 + 0.7 * criticality)
        * exposure_factor(enterprise)
        * version_risk_factor(enterprise)
        * confidence_factor
    )
    return round(clamp(raw), 1)


def score_record(record: Dict[str, Any]) -> Dict[str, Any]:
    scored = dict(record)
    scored["scores"] = dict(record.get("scores", {}))
    vitality = scored["scores"].get("oss_vitality")
    if vitality is None:
        vitality = calculate_oss_vitality(scored)
        scored["scores"]["oss_vitality"] = vitality
    if scored["scores"].get("enterprise_priority_risk") is None:
        scored["scores"]["enterprise_priority_risk"] = calculate_enterprise_priority(scored, float(vitality))
    if scored["scores"].get("undermaintenance_pressure") is None:
        scored["scores"]["undermaintenance_pressure"] = calculate_undermaintenance_pressure(scored)
    return scored


def iter_records(payload: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        yield from payload["records"]
    elif isinstance(payload, list):
        yield from payload
    else:
        raise ValueError("Input must be a JSON array or an object with records[]")


def main() -> int:
    parser = argparse.ArgumentParser(description="Score OSS library risk records.")
    parser.add_argument("input", type=Path, help="Path to OSS risk records JSON")
    parser.add_argument("--output", type=Path, help="Optional path for scored JSON")
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    scored_records: List[Dict[str, Any]] = [score_record(record) for record in iter_records(payload)]

    output_payload = {"schema_version": "0.1", "records": scored_records}
    if args.output:
        args.output.write_text(json.dumps(output_payload, indent=2) + "\n", encoding="utf-8")
    else:
        for record in scored_records:
            project = record["project"]["name"]
            scores = record["scores"]
            print(
                f"{project}: OSS vitality {scores['oss_vitality']:.1f}, "
                f"enterprise priority {scores['enterprise_priority_risk']:.1f}, "
                f"UMP {scores['undermaintenance_pressure']:.2f}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

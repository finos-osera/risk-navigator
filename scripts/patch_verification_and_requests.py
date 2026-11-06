#!/usr/bin/env python3
"""Track patch plans through deployment and verify realized remediation (#28), and export/deduplicate private estate coverage requests (#29, #42).

Implements:
- #28: Lifecycle stages (`suggested`, `planned`, `tested`, `deployed`, `verified`, plus `exception`,
  `reopened_rollback`, `reopened_withdrawn_artifact`, `validation_failed`, `partial_rollout_with_stale_inventory`).
  Binds plans to source snapshots, policy, and selected artifact identity/digest. Never credits recipe generation,
  ticket closure, OSERA issue closure, or reference-graph changes as member remediation. Separates planned benefit,
  observed remediation, and changes caused only by inventory/scope drift.
- #29 & #42: Versioned coverage request export (`osera-coverage-request/v1`), strict ecosystem validation (never
  silently coercing unknown ecosystems to Maven), broad-major vs exact-line precision preservation, explicit
  co-released artifact group mapping, authenticated intake deduplication boundary with rare-request k-anonymity
  privacy protection, and evidence-based request lifecycle tracking (`draft`, `exported`, `submitted_acknowledged`,
  `in_progress`, `covered`) that links released coverage back to estate opportunities without inflating adoption metrics.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from patch_feeds import ECOSYSTEM_LABELS, parse_purl

PATCH_PLAN_SCHEMA_VERSION = "osera-patch-plan/v1"
PATCH_RECONCILIATION_SCHEMA_VERSION = "osera-patch-reconciliation-report/v1"
COVERAGE_REQUEST_SCHEMA_VERSION = "osera-coverage-request/v1"
INTAKE_AGGREGATION_SCHEMA_VERSION = "osera-coverage-intake-summary/v1"

VALID_LIFECYCLE_STAGES = (
    "suggested",
    "planned",
    "tested",
    "deployed",
    "verified",
    "exception",
    "partial_rollout",
    "partial_rollout_with_stale_inventory",
    "validation_failed",
    "reopened_rollback",
    "reopened_withdrawn_artifact",
    "reopened_invalidated_evidence",
)

SUPPORTED_REQUEST_ECOSYSTEMS = frozenset(ECOSYSTEM_LABELS.keys())
ADVISORY_ID_RE = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.IGNORECASE)
PRIVATE_ESTATE_KEYS = frozenset(
    {
        "application_id",
        "applications",
        "affected_applications",
        "consumer_project_ids",
        "direct_consumer_project_ids",
        "owner",
        "owners",
        "dependency_path",
        "dependency_paths",
        "contract_id",
        "pricing",
        "internal_repository_url",
        "scope_name",
    }
)


# ============================================================================
# #28 — Patch Plan Lifecycle & Realized Remediation Verification
# ============================================================================


def reconcile_patch_plans_with_observations(
    bundle_or_path: dict[str, Any] | Path,
) -> dict[str, Any]:
    """Reconcile executed patch plans against new SBOM/build/deployment observations and feed updates (#28).

    Enforces #28 acceptance criteria:
    1. A closed ticket (`ticket_status == 'closed'`), OSERA issue closure (`osera_issue_status == 'closed'`),
       or recipe generation (`recipe_generated == True`) without deployment evidence CANNOT mark exposure
       `verified` as removed.
    2. Observed target identity (`purl` + optional `artifact_digest`) and relevant deployment scope (`environment`,
       `application_id`) are checked before crediting benefit.
    3. Partial rollout, stale inventory (`observation_timestamp < stale_cutoff`), and failed validation produce
       explicit states and residual exposure.
    4. Rollback (`observed_version == previous_version` after prior deployment) and artifact withdrawal
       (`withdrawn == True` in active catalog) reopen the relevant opportunity with a clear explanation.
    5. Reports strictly separate `planned_benefit`, `observed_remediation`, and `inventory_or_scope_drift`.
    """
    if isinstance(bundle_or_path, Path):
        payload = json.loads(bundle_or_path.read_text(encoding="utf-8"))
    else:
        payload = copy.deepcopy(bundle_or_path)

    stale_cutoff = str(payload.get("stale_inventory_cutoff") or "2026-10-20T00:00:00Z")
    withdrawn_purls = set(str(x) for x in (payload.get("withdrawn_artifacts") or []) if str(x).strip())
    invalidated_advisories = set(str(x) for x in (payload.get("invalidated_advisory_claims") or []) if str(x).strip())

    # Index latest deployment observations by (application_id, environment, library)
    observations_by_app: dict[str, dict[str, Any]] = {}
    for obs in payload.get("deployment_observations") or []:
        if not isinstance(obs, dict):
            continue
        app_id = str(obs.get("application_id") or "").strip()
        if app_id:
            observations_by_app[app_id] = obs

    reconciled_plans: list[dict[str, Any]] = []
    total_planned_benefit = 0
    total_observed_remediation = 0
    total_scope_drift_count = 0

    for plan in payload.get("plans") or []:
        if not isinstance(plan, dict):
            continue
        plan_id = str(plan.get("plan_id") or "plan").strip()
        opp_id = str(plan.get("opportunity_id") or plan_id).strip()
        prior_stage = str(plan.get("current_stage") or "planned").strip().lower()
        source_snapshot_id = str(plan.get("source_snapshot_id") or "snapshot-unknown")
        policy_binding = plan.get("policy_binding") if isinstance(plan.get("policy_binding"), dict) else {}
        selected_purl = str(plan.get("selected_artifact_purl") or "").strip()
        selected_digest = str(plan.get("selected_artifact_digest") or "").strip() or None
        source_purl = str(plan.get("source_artifact_purl") or "").strip()
        required_env = str(plan.get("required_environment") or "production").strip().lower()

        target_apps = [str(a).strip() for a in (plan.get("target_applications") or []) if str(a).strip()]
        expected_advisories = [str(a).strip() for a in (plan.get("expected_fixed_advisories") or []) if str(a).strip()]
        planned_exposures = [f"{app}|{adv}" for app in target_apps for adv in expected_advisories]
        total_planned_benefit += len(planned_exposures)

        # Non-evidence signals that MUST NEVER be credited as deployment remediation (#28)
        ticket_status = str(plan.get("ticket_status") or "open").strip().lower()
        osera_issue_status = str(plan.get("osera_issue_status") or "open").strip().lower()
        recipe_generated = bool(plan.get("recipe_generated", False))
        reference_graph_updated = bool(plan.get("reference_graph_updated", False))

        if prior_stage == "exception" or plan.get("exception_approved") is True:
            reconciled_plans.append(
                {
                    "plan_id": plan_id,
                    "opportunity_id": opp_id,
                    "source_snapshot_id": source_snapshot_id,
                    "policy_binding": policy_binding,
                    "selected_artifact_purl": selected_purl,
                    "prior_stage": prior_stage,
                    "reconciled_stage": "exception",
                    "opportunity_reopened": False,
                    "reopened_reason": None,
                    "planned_benefit_exposures": planned_exposures,
                    "observed_remediated_exposures": [],
                    "residual_exposures": planned_exposures,
                    "inventory_or_scope_drift_exposures": [],
                    "non_deployment_signals_ignored": {
                        "ticket_status": ticket_status,
                        "osera_issue_status": osera_issue_status,
                        "recipe_generated": recipe_generated,
                        "reference_graph_updated": reference_graph_updated,
                    },
                }
            )
            continue

        # Check if artifact was withdrawn in feed
        artifact_withdrawn = selected_purl in withdrawn_purls or bool(plan.get("artifact_withdrawn", False))
        if artifact_withdrawn:
            total_residual = list(planned_exposures)
            reconciled_plans.append(
                {
                    "plan_id": plan_id,
                    "opportunity_id": opp_id,
                    "source_snapshot_id": source_snapshot_id,
                    "policy_binding": policy_binding,
                    "selected_artifact_purl": selected_purl,
                    "prior_stage": prior_stage,
                    "reconciled_stage": "reopened_withdrawn_artifact",
                    "opportunity_reopened": True,
                    "reopened_reason": f"Selected patch artifact {selected_purl} was withdrawn by provider; opportunity {opp_id} reopened.",
                    "planned_benefit_exposures": planned_exposures,
                    "observed_remediated_exposures": [],
                    "residual_exposures": total_residual,
                    "inventory_or_scope_drift_exposures": [],
                    "non_deployment_signals_ignored": {
                        "ticket_status": ticket_status,
                        "osera_issue_status": osera_issue_status,
                        "recipe_generated": recipe_generated,
                        "reference_graph_updated": reference_graph_updated,
                    },
                }
            )
            continue

        verified_apps: list[str] = []
        deployed_unverified_apps: list[str] = []
        failed_validation_apps: list[str] = []
        rolled_back_apps: list[str] = []
        stale_inventory_apps: list[str] = []
        unpatched_apps: list[str] = []
        scope_drift_apps: list[str] = []

        for app_id in target_apps:
            obs = observations_by_app.get(app_id)
            if obs is None or bool(obs.get("removed_from_scope", False)):
                # Missing from inventory / decommissioned scope drift — NEVER credit as observed remediation!
                scope_drift_apps.append(app_id)
                continue

            obs_purl = str(obs.get("observed_purl") or "").strip()
            obs_digest = str(obs.get("observed_artifact_digest") or "").strip() or None
            obs_env = str(obs.get("environment") or "production").strip().lower()
            obs_ts = str(obs.get("observed_at") or "")
            validation_status = str(obs.get("validation_status") or "pending").strip().lower()
            previously_deployed = bool(obs.get("previously_deployed_target", False)) or prior_stage == "verified"

            is_stale = bool(obs_ts and obs_ts < stale_cutoff)
            if is_stale:
                stale_inventory_apps.append(app_id)

            identity_matches = (
                obs_purl == selected_purl
                and obs_env == required_env
                and (selected_digest is None or obs_digest == selected_digest)
            )

            if identity_matches:
                if validation_status == "failed":
                    failed_validation_apps.append(app_id)
                elif validation_status == "passed" and not is_stale:
                    verified_apps.append(app_id)
                else:
                    deployed_unverified_apps.append(app_id)
            else:
                if previously_deployed and obs_purl == source_purl:
                    rolled_back_apps.append(app_id)
                else:
                    unpatched_apps.append(app_id)

        observed_remediated = [
            f"{app}|{adv}"
            for app in verified_apps
            for adv in expected_advisories
            if adv not in invalidated_advisories
        ]
        drift_exposures = [f"{app}|{adv}" for app in scope_drift_apps for adv in expected_advisories]
        residual_exposures = [
            exp for exp in planned_exposures if exp not in set(observed_remediated) and exp not in set(drift_exposures)
        ]

        total_observed_remediation += len(observed_remediated)
        total_scope_drift_count += len(drift_exposures)

        reopened = False
        reopened_reason: str | None = None

        if rolled_back_apps:
            reconciled_stage = "reopened_rollback"
            reopened = True
            reopened_reason = (
                f"Deployment rollback detected on {', '.join(rolled_back_apps)} "
                f"(reverted from {selected_purl} to {source_purl}); opportunity {opp_id} reopened."
            )
        elif failed_validation_apps:
            reconciled_stage = "validation_failed"
            reopened = True
            reopened_reason = (
                f"Post-deployment validation failed on {', '.join(failed_validation_apps)} for {selected_purl}."
            )
        elif verified_apps and len(verified_apps) == len(target_apps) and not residual_exposures:
            reconciled_stage = "verified"
        elif verified_apps or deployed_unverified_apps:
            if len(verified_apps) + len(deployed_unverified_apps) < len(target_apps) - len(scope_drift_apps):
                reconciled_stage = (
                    "partial_rollout_with_stale_inventory" if stale_inventory_apps else "partial_rollout"
                )
            elif stale_inventory_apps:
                reconciled_stage = "partial_rollout_with_stale_inventory"
            else:
                reconciled_stage = "deployed"
        elif scope_drift_apps and len(scope_drift_apps) == len(target_apps):
            reconciled_stage = "inventory_scope_drift_only"
        else:
            # Even if ticket_status == 'closed' or osera_issue_status == 'closed' or recipe_generated == True,
            # without deployment evidence the stage remains 'planned' (or 'tested') and NEVER 'verified'!
            reconciled_stage = "tested" if prior_stage == "tested" else "planned"

        reconciled_plans.append(
            {
                "plan_id": plan_id,
                "opportunity_id": opp_id,
                "source_snapshot_id": source_snapshot_id,
                "policy_binding": policy_binding,
                "selected_artifact_purl": selected_purl,
                "selected_artifact_digest": selected_digest,
                "prior_stage": prior_stage,
                "reconciled_stage": reconciled_stage,
                "opportunity_reopened": reopened,
                "reopened_reason": reopened_reason,
                "application_breakdown": {
                    "verified_applications": verified_apps,
                    "deployed_unverified_applications": deployed_unverified_apps,
                    "failed_validation_applications": failed_validation_apps,
                    "rolled_back_applications": rolled_back_apps,
                    "stale_inventory_applications": stale_inventory_apps,
                    "unpatched_applications": unpatched_apps,
                    "scope_drift_applications": scope_drift_apps,
                },
                "planned_benefit_exposures": planned_exposures,
                "observed_remediated_exposures": observed_remediated,
                "residual_exposures": residual_exposures,
                "inventory_or_scope_drift_exposures": drift_exposures,
                "non_deployment_signals_ignored": {
                    "ticket_status": ticket_status,
                    "osera_issue_status": osera_issue_status,
                    "recipe_generated": recipe_generated,
                    "reference_graph_updated": reference_graph_updated,
                },
            }
        )

    return {
        "schema_version": PATCH_RECONCILIATION_SCHEMA_VERSION,
        "summary": {
            "total_plans": len(reconciled_plans),
            "verified_plan_count": sum(1 for p in reconciled_plans if p["reconciled_stage"] == "verified"),
            "reopened_plan_count": sum(1 for p in reconciled_plans if p["opportunity_reopened"]),
            "planned_benefit_exposure_count": total_planned_benefit,
            "observed_remediated_exposure_count": total_observed_remediation,
            "inventory_or_scope_drift_exposure_count": total_scope_drift_count,
            "residual_exposure_count": sum(len(p["residual_exposures"]) for p in reconciled_plans),
        },
        "plans": reconciled_plans,
    }


# ============================================================================
# #29 & #42 — Private Estate Coverage Request Export, Co-Release Grouping & Intake
# ============================================================================


def validate_and_normalize_coverage_request(
    raw_req: dict[str, Any],
    co_released_group_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate a manual or inventory-derived OSERA coverage request (#29, #42).

    Enforces:
    - Unknown line identity or unsupported ecosystem is explicitly rejected rather than silently expanded
      or coerced to Maven.
    - Broad-major (`N.x`) vs minor (`N.N.x`) vs exact-line (`N.N.N`) precision is preserved explicitly;
      broad-major requests are NEVER silently expanded into confirmed exact-line inventory.
    - Co-released artifacts are grouped ONLY through an explicit `co_released_group_mapping`.
    """
    raw_purl = str(raw_req.get("identity") or raw_req.get("purl") or "").strip()
    explicit_eco = str(raw_req.get("ecosystem") or "").strip().lower()

    if raw_purl.startswith("pkg:"):
        m = re.match(r"^pkg:([a-z0-9.+-]+)/([^@#?]+)(?:@([^?#]+))?", raw_purl, re.IGNORECASE)
        if not m:
            raise ValueError(f"Invalid package URL in coverage request: {raw_purl}")
        eco = m.group(1).lower()
        pkg_path = m.group(2)
        ver = m.group(3) or ""
        if eco not in SUPPORTED_REQUEST_ECOSYSTEMS:
            raise ValueError(f"Unsupported ecosystem '{eco}'; refusing to silently coerce to Maven.")
        parsed = parse_purl(raw_purl) if ver else {
            "valid": True,
            "ecosystem_type": eco,
            "library": pkg_path.replace("/", ":") if eco == "maven" and "/" in pkg_path else pkg_path,
            "version": "",
        }
    else:
        if not explicit_eco:
            raise ValueError("Missing explicit ecosystem or PURL; refusing to silently coerce to Maven.")
        if explicit_eco not in SUPPORTED_REQUEST_ECOSYSTEMS:
            raise ValueError(f"Unsupported ecosystem '{explicit_eco}'; refusing to silently coerce to Maven.")
        eco = explicit_eco
        lib = str(raw_req.get("package") or raw_req.get("library") or "").strip()
        ver = str(raw_req.get("version") or "").strip()
        if not lib:
            raise ValueError("Coverage request requires a package coordinate.")
        parsed = {
            "valid": True,
            "ecosystem_type": eco,
            "library": lib,
            "version": ver,
        }

    precision = str(raw_req.get("precision") or "exact").strip().lower()
    if precision not in ("exact", "minor", "major"):
        raise ValueError(f"Invalid line precision '{precision}'; must be 'exact', 'minor', or 'major'.")

    line_val = str(raw_req.get("line") or "").strip()
    if not line_val:
        raise ValueError("Missing requested maintenance line or version.")
    if precision == "exact" and parsed["version"] and line_val != parsed["version"]:
        raise ValueError(f"Exact precision line '{line_val}' must match version '{parsed['version']}'.")
    if precision == "minor" and not re.match(r"^\d+\.\d+\.x$", line_val):
        raise ValueError(f"Minor line '{line_val}' must match 'N.N.x'.")
    if precision == "major" and not re.match(r"^\d+\.x$", line_val):
        raise ValueError(f"Major line '{line_val}' must match 'N.x'.")

    advisories = sorted(
        {
            str(a).strip()
            for a in (raw_req.get("advisories") or [])
            if str(a).strip()
        }
    )
    if not advisories or any(not ADVISORY_ID_RE.match(a) for a in advisories):
        raise ValueError("Coverage request requires at least one valid CVE or GHSA advisory ID.")

    remediation_classes = sorted(
        {
            str(r).strip().lower()
            for r in (raw_req.get("acceptable_remediation") or raw_req.get("remediation") or ["backpatch"])
            if str(r).strip()
        }
    )
    valid_classes = {"backpatch", "upstream-fix", "replacement"}
    if not remediation_classes or any(r not in valid_classes for r in remediation_classes):
        raise ValueError(f"Unsupported remediation class in {remediation_classes}.")

    pkg_coord = f"pkg:{eco}/{parsed['library'].replace(':', '/')}"
    group_map = co_released_group_mapping or {}
    co_release_group = group_map.get(pkg_coord) or group_map.get(parsed["library"]) or None

    return {
        "package": pkg_coord,
        "ecosystem": eco,
        "library": parsed["library"],
        "scope": {
            "precision": precision,
            "value": line_val,
            "confirmed_exact_inventory": precision == "exact",
        },
        "co_release_group": co_release_group,
        "advisories": advisories,
        "acceptable_remediation": remediation_classes,
        "rationale": str(raw_req.get("rationale") or "").strip()[:2000] or None,
        "incompatibility": str(raw_req.get("incompatibility") or "").strip()[:2000] or None,
    }


def build_privacy_preserving_request_export(
    raw_requests: list[dict[str, Any]],
    *,
    existing_catalog_patches: list[dict[str, Any]] | None = None,
    existing_osera_work: list[dict[str, Any]] | None = None,
    co_released_group_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Export a versioned, privacy-preserving coverage request bundle (`osera-coverage-request/v1`) (#29, #42).

    Enforces:
    - Excludes all private estate fields (`application_id`, `owner`, `dependency_path`, `contract_id`, `scope_name`).
    - Merges repeated compatible requests for the same `(package, precision, line)` without duplicating demand,
      while keeping different maintenance lines or precisions strictly separate.
    - Distinguishes existing coverage and unresolved new work on an already supported line.
    - Links requests to subsequent OSERA work/released coverage (`lifecycle_state`) without equating released
      coverage with member deployment (`counts_as_member_deployment: False`).
    """
    catalog = existing_catalog_patches or []
    work_items = existing_osera_work or []

    merged_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in raw_requests:
        norm = validate_and_normalize_coverage_request(raw, co_released_group_mapping)
        key = (norm["package"], norm["scope"]["precision"], norm["scope"]["value"])
        if key not in merged_by_key:
            merged_by_key[key] = copy.deepcopy(norm)
            merged_by_key[key]["_lifecycle_hint"] = str(raw.get("lifecycle_state") or "draft").strip().lower()
        else:
            existing = merged_by_key[key]
            existing["advisories"] = sorted(set(existing["advisories"]) | set(norm["advisories"]))
            existing["acceptable_remediation"] = sorted(
                set(existing["acceptable_remediation"]) | set(norm["acceptable_remediation"])
            )
            if norm["rationale"] and not existing["rationale"]:
                existing["rationale"] = norm["rationale"]
            if norm["incompatibility"] and not existing["incompatibility"]:
                existing["incompatibility"] = norm["incompatibility"]

    exported_requests: list[dict[str, Any]] = []
    for key, item in merged_by_key.items():
        pkg, precision, line_val = key
        # Check existing catalog coverage on this line (only exact-line precision can be confirmed covered)
        matching_patches = [
            p
            for p in catalog
            if isinstance(p, dict)
            and p.get("package") == pkg
            and p.get("release_state", "released") == "released"
            and (precision == "exact" and line_val in (p.get("applicable_versions") or []))
        ]
        covered_advisories = {
            str(a).strip()
            for p in matching_patches
            for a in (p.get("fixed_advisories") or [])
        }
        unresolved_advisories = [a for a in item["advisories"] if a not in covered_advisories]

        matching_work = [
            w
            for w in work_items
            if isinstance(w, dict)
            and w.get("package") == pkg
            and w.get("line") == line_val
        ]

        # Determine evidence-based lifecycle state (#42)
        released_targets = [str(p.get("replacement_purl") or p.get("target") or "") for p in matching_patches if p.get("replacement_purl") or p.get("target")]
        if precision == "exact" and covered_advisories and not unresolved_advisories:
            line_coverage_status = "existing_full_coverage"
            lifecycle_state = "covered"
        elif precision == "exact" and covered_advisories and unresolved_advisories:
            line_coverage_status = "supported_line_with_unresolved_new_work"
            lifecycle_state = "in_progress" if matching_work else "exported"
        elif matching_work:
            work_statuses = {str(w.get("status") or "").lower() for w in matching_work}
            line_coverage_status = "existing_osera_work_in_progress"
            lifecycle_state = "in_progress" if "in_progress" in work_statuses else "submitted_acknowledged"
        else:
            line_coverage_status = "broad_major_line_review_required" if precision == "major" else "unmet_line_demand"
            lifecycle_state = "exported"

        # Allowlist-only public request entry — zero private estate fields!
        req_entry: dict[str, Any] = {
            "package": item["package"],
            "ecosystem": item["ecosystem"],
            "scope": item["scope"],
            "requested_advisories": item["advisories"],
            "already_covered_advisories": sorted(covered_advisories & set(item["advisories"])),
            "unresolved_advisories": unresolved_advisories if precision == "exact" else item["advisories"],
            "acceptable_remediation": item["acceptable_remediation"],
            "line_coverage_status": line_coverage_status,
            "lifecycle_state": lifecycle_state,
            "linked_osera_work_urls": [str(w.get("url")) for w in matching_work if w.get("url")],
            "linked_released_patches": released_targets,
            "counts_as_member_deployment": False,
        }
        if item["co_release_group"]:
            req_entry["co_release_group"] = item["co_release_group"]
        if item["rationale"]:
            req_entry["rationale"] = item["rationale"]
        if item["incompatibility"]:
            req_entry["incompatibility"] = item["incompatibility"]

        exported_requests.append(req_entry)

    bundle = {
        "schema_version": COVERAGE_REQUEST_SCHEMA_VERSION,
        "kind": "osera-coverage-request",
        "submission_status": "local_export_not_submitted",
        "requests": exported_requests,
    }

    # Verify zero private keys leaked into serialized bundle
    serialized = json.dumps(bundle)
    for forbidden in PRIVATE_ESTATE_KEYS:
        if f'"{forbidden}"' in serialized:
            raise AssertionError(f"Privacy boundary violation: forbidden key {forbidden} found in export.")

    return bundle


def deduplicate_authenticated_intake_submissions(
    submissions: list[dict[str, Any]],
    *,
    min_k_anonymity_members: int = 2,
) -> dict[str, Any]:
    """Deduplicate member demand per line at the authenticated OSERA intake boundary and enforce rare-request privacy (#29).

    Enforces:
    - Repeated submissions from the same authenticated member (`member_auth_id`) for the same `(package, line)`
      do NOT inflate consortium demand (`unique_member_demand_count`).
    - Attribution is stripped at the intake boundary (`member_auth_id` never appears in public output).
    - Rare requests with `unique_member_demand_count < min_k_anonymity_members` have their free-text rationale
      withheld in public output (`rare_request_privacy_redacted: True`) to prevent member re-identification.
    """
    demand_by_line: dict[tuple[str, str, str], dict[str, Any]] = {}

    for sub in submissions:
        if not isinstance(sub, dict):
            continue
        member_id = str(sub.get("member_auth_id") or "").strip()
        if not member_id:
            raise ValueError("Intake boundary requires an authenticated member_auth_id.")
        bundle = sub.get("bundle") if isinstance(sub.get("bundle"), dict) else sub
        for req in bundle.get("requests") or []:
            if not isinstance(req, dict):
                continue
            pkg = str(req.get("package") or "").strip()
            scope = req.get("scope") if isinstance(req.get("scope"), dict) else {}
            prec = str(scope.get("precision") or "exact").strip()
            line_val = str(scope.get("value") or "").strip()
            key = (pkg, prec, line_val)
            if key not in demand_by_line:
                demand_by_line[key] = {
                    "package": pkg,
                    "scope": {"precision": prec, "value": line_val},
                    "members": set(),
                    "submission_attempts": 0,
                    "advisories": set(),
                    "rationales": [],
                }
            entry = demand_by_line[key]
            entry["submission_attempts"] += 1
            entry["members"].add(member_id)
            for adv in req.get("unresolved_advisories") or req.get("requested_advisories") or req.get("advisories") or []:
                entry["advisories"].add(str(adv).strip())
            if req.get("rationale"):
                entry["rationales"].append(str(req["rationale"]))

    public_accepted_lines: list[dict[str, Any]] = []
    for key in sorted(demand_by_line.keys()):
        entry = demand_by_line[key]
        member_count = len(entry["members"])
        is_rare = member_count < min_k_anonymity_members
        public_accepted_lines.append(
            {
                "package": entry["package"],
                "scope": entry["scope"],
                "unique_member_demand_count": member_count,
                "duplicate_submissions_collapsed": entry["submission_attempts"] - member_count,
                "advisories": sorted(entry["advisories"]),
                "rare_request_privacy_redacted": is_rare,
                "public_rationale_summary": (
                    "Redacted under rare-request k-anonymity threshold"
                    if is_rare
                    else (entry["rationales"][0] if entry["rationales"] else None)
                ),
            }
        )

    return {
        "schema_version": INTAKE_AGGREGATION_SCHEMA_VERSION,
        "min_k_anonymity_members": min_k_anonymity_members,
        "public_lines": public_accepted_lines,
    }

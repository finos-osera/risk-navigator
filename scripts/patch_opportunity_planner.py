#!/usr/bin/env python3
"""Rank eligible patch opportunities (#26) and provide an actionable opportunity queue and portfolio planner (#27).

Implements:
- #26: Rank eligible patch opportunities using OSERA rules (`rules/prioritisation.yaml` P0/P1/P2 baseline)
  and company priorities (SLA, criticality, exposure, change constraints), keeping EPSS percentile distinct from
  probability, retaining CVSS version/provenance, preserving unknown signals as `'unknown'` (never zero risk),
  computing incremental portfolio credit across overlapping library and framework/BOM fixes, and keeping
  estimated effort, confidence, and measured outcomes separate.
- #27: Actionable patch opportunity queues (`ready_to_plan`, `blocked`, `investigate`, `request_coverage`),
  side-by-side provider comparison drawer (upstream, commercial, OSERA + rejection reasons), portfolio assembly
  by owner, framework/runtime, and change window, safe OpenRewrite recipe suppression for transitive/unknown
  dependency paths, and owner-ready change package export with coordinates, dependencies, evidence,
  implementation instructions, required validation, and rollback target.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from patch_feeds import parse_purl

OPPORTUNITY_PLANNER_SCHEMA_VERSION = "osera-opportunity-planner/v1"
OSERA_PRIORITISATION_RULES_VERSION = "osera-prioritisation-rules/v1"
CHANGE_PACKAGE_SCHEMA_VERSION = "osera-owner-change-package/v1"

QUEUE_READY_TO_PLAN = "ready_to_plan"
QUEUE_BLOCKED = "blocked"
QUEUE_INVESTIGATE = "investigate"
QUEUE_REQUEST_COVERAGE = "request_coverage"

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "UNRANKED": 9}
EFFORT_ORDER = {"low": 1, "medium": 2, "high": 3, "unknown": 4}
CRITICALITY_WEIGHT = {"tier_1_critical": 30, "high": 20, "medium": 10, "low": 0, "unknown": 5}


def _canonical_advisory_map(advisory_records: list[dict[str, Any]]) -> Any:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        if x not in parent:
            parent[x] = x
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rb.upper().startswith("CVE-") and not ra.upper().startswith("CVE-"):
            parent[ra] = rb
        else:
            parent[rb] = ra

    for rec in advisory_records:
        cid = str(rec.get("id") or rec.get("cve_id") or rec.get("advisory_id") or "").strip()
        for al in rec.get("aliases") or []:
            al_str = str(al).strip()
            if cid and al_str:
                union(cid, al_str)

    return find


def evaluate_osera_priority(
    advisories: list[dict[str, Any]],
    rules_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate OSERA baseline inclusion and P0/P1/P2 priority per `rules/prioritisation.yaml` (#26).

    Rules:
    - P0: Any CISA KEV finding (`kev == True`), OR CVSS >= 9.0 (Critical), OR High CVSS (>= 7.0) with
          `epss_probability >= 0.20` (or `epss_percentile >= 0.95`).
    - P1: High CVSS (`7.0 <= cvss < 9.0`) without P0 trigger, OR **medium-with-signal** (`4.0 <= cvss < 7.0`
          accompanied by `epss_probability >= 0.08`, `epss_percentile >= 0.90`, or `exploit_maturity` in
          `("poc", "active", "weaponized", "high")`).
    - P2: Standard Medium (`4.0 <= cvss < 7.0` without elevated signal), Low (`0 < cvss < 4.0`), or
          advisories with unknown numeric CVSS/EPSS signals (never treated as zero risk!).
    """
    cfg = rules_config or {}
    rules_version = str(cfg.get("rules_version") or "2026.10-osera-prioritisation-v1")

    if not advisories:
        return {
            "included": False,
            "priority": "UNRANKED",
            "rule_id": "OSERA-NONE",
            "rules_version": rules_version,
            "reason": "No vulnerability advisories observed on component.",
            "unknown_signal_advisories": [],
            "signal_summary": {
                "kev_count": 0,
                "max_cvss_score": "unknown",
                "max_epss_probability": "unknown",
                "max_epss_percentile": "unknown",
                "cvss_provenance": [],
            },
        }

    kev_ids: list[str] = []
    p0_reasons: list[str] = []
    p1_reasons: list[str] = []
    p2_reasons: list[str] = []
    unknown_signal_ids: list[str] = []
    cvss_provenance: list[dict[str, Any]] = []

    max_cvss: float | None = None
    max_epss_prob: float | None = None
    max_epss_pct: float | None = None

    for adv in advisories:
        adv_id = str(adv.get("id") or adv.get("cve_id") or adv.get("advisory_id") or "UNKNOWN").strip()
        is_kev = bool(adv.get("kev", False))
        cvss_raw = adv.get("cvss_score") if adv.get("cvss_score") is not None else adv.get("cvss")
        cvss_score = float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None
        cvss_ver = str(adv.get("cvss_version") or ("3.1" if cvss_score is not None else "unknown"))
        cvss_src = str(adv.get("cvss_source") or ("NVD/OSV" if cvss_score is not None else "unknown"))

        # Keep EPSS probability strictly distinct from EPSS percentile (#26)
        epss_prob_raw = adv.get("epss_probability")
        epss_pct_raw = adv.get("epss_percentile")
        epss_prob = float(epss_prob_raw) if isinstance(epss_prob_raw, (int, float)) else None
        epss_pct = float(epss_pct_raw) if isinstance(epss_pct_raw, (int, float)) else None
        exploit_signal = str(adv.get("exploit_maturity") or adv.get("signal") or "").strip().lower()

        cvss_provenance.append(
            {
                "advisory_id": adv_id,
                "cvss_score": cvss_score if cvss_score is not None else "unknown",
                "cvss_version": cvss_ver,
                "cvss_source": cvss_src,
                "epss_probability": epss_prob if epss_prob is not None else "unknown",
                "epss_percentile": epss_pct if epss_pct is not None else "unknown",
            }
        )

        if cvss_score is None or (epss_prob is None and epss_pct is None):
            unknown_signal_ids.append(adv_id)

        if cvss_score is not None and (max_cvss is None or cvss_score > max_cvss):
            max_cvss = cvss_score
        if epss_prob is not None and (max_epss_prob is None or epss_prob > max_epss_prob):
            max_epss_prob = epss_prob
        if epss_pct is not None and (max_epss_pct is None or epss_pct > max_epss_pct):
            max_epss_pct = epss_pct

        if is_kev:
            kev_ids.append(adv_id)
            p0_reasons.append(f"{adv_id}: CISA KEV active exploitation catalog (OSERA-P0-KEV)")
        elif cvss_score is not None and cvss_score >= 9.0:
            p0_reasons.append(f"{adv_id}: Critical CVSS {cvss_score:.1f} v{cvss_ver} (OSERA-P0-CRITICAL)")
        elif cvss_score is not None and cvss_score >= 7.0 and (
            (epss_prob is not None and epss_prob >= 0.20) or (epss_pct is not None and epss_pct >= 0.95)
        ):
            p0_reasons.append(
                f"{adv_id}: High CVSS {cvss_score:.1f} with elevated EPSS (prob={epss_prob}, pct={epss_pct}) (OSERA-P0-HIGH-EPSS)"
            )
        elif cvss_score is not None and cvss_score >= 7.0:
            p1_reasons.append(f"{adv_id}: High CVSS {cvss_score:.1f} v{cvss_ver} (OSERA-P1-HIGH)")
        elif cvss_score is not None and 4.0 <= cvss_score < 7.0 and (
            (epss_prob is not None and epss_prob >= 0.08)
            or (epss_pct is not None and epss_pct >= 0.90)
            or exploit_signal in ("poc", "active", "weaponized", "high", "epss_spike")
        ):
            p1_reasons.append(
                f"{adv_id}: Medium CVSS {cvss_score:.1f} with exploitability signal (prob={epss_prob}, pct={epss_pct}, signal={exploit_signal or 'epss'}) (OSERA-P1-MEDIUM-WITH-SIGNAL)"
            )
        elif cvss_score is None:
            p2_reasons.append(f"{adv_id}: Missing CVSS score treated as unknown severity, never zero risk (OSERA-P2-UNKNOWN-SEVERITY)")
        else:
            p2_reasons.append(f"{adv_id}: Standard Medium/Low CVSS {cvss_score:.1f} (OSERA-P2-BASELINE)")

    if p0_reasons:
        priority = "P0"
        rule_id = "OSERA-P0-KEV" if kev_ids else "OSERA-P0-CRITICAL-OR-HIGH-EPSS"
        reason = "; ".join(p0_reasons)
    elif p1_reasons:
        priority = "P1"
        rule_id = (
            "OSERA-P1-MEDIUM-WITH-SIGNAL"
            if any("OSERA-P1-MEDIUM-WITH-SIGNAL" in r for r in p1_reasons)
            else "OSERA-P1-HIGH"
        )
        reason = "; ".join(p1_reasons)
    else:
        priority = "P2"
        rule_id = "OSERA-P2-BASELINE"
        reason = "; ".join(p2_reasons)

    return {
        "included": True,
        "priority": priority,
        "rule_id": rule_id,
        "rules_version": rules_version,
        "reason": reason,
        "unknown_signal_advisories": sorted(set(unknown_signal_ids)),
        "signal_summary": {
            "kev_count": len(kev_ids),
            "max_cvss_score": max_cvss if max_cvss is not None else "unknown",
            "max_epss_probability": max_epss_prob if max_epss_prob is not None else "unknown",
            "max_epss_percentile": max_epss_pct if max_epss_pct is not None else "unknown",
            "cvss_provenance": cvss_provenance,
        },
    }


def _classify_queue_and_next_step(raw_opp: dict[str, Any]) -> dict[str, Any]:
    """Classify an opportunity into Ready to plan, Blocked, Investigate, or Request coverage (#26, #27)."""
    identity_status = str(raw_opp.get("identity_status") or "confirmed").strip().lower()
    blockers: list[str] = [str(b) for b in (raw_opp.get("blockers") or []) if str(b).strip()]
    selected_option = raw_opp.get("selected_option") if isinstance(raw_opp.get("selected_option"), dict) else None
    options = [o for o in (raw_opp.get("options") or []) if isinstance(o, dict)]
    if selected_option is None and options:
        ready_opts = [o for o in options if o.get("ready") is True]
        selected_option = ready_opts[0] if ready_opts else options[0]

    # Check identity & applicability gates first
    if identity_status in ("ambiguous", "unverified", "missing_version", "unknown"):
        if "ambiguous_package_identity" not in blockers:
            blockers.append("ambiguous_package_identity")
        return {
            "queue": QUEUE_INVESTIGATE,
            "eligible_for_ready_ranking": False,
            "blockers": blockers,
            "next_step": "Resolve exact package PURL, version, and dependency graph from lockfile or build SBOM.",
            "evidence_needed": ["build_sbom_with_exact_purl", "resolved_dependency_lockfile"],
            "selected_option": selected_option,
        }

    if not options:
        if "no_known_patch_in_catalog" not in blockers:
            blockers.append("no_known_patch_in_catalog")
        return {
            "queue": QUEUE_REQUEST_COVERAGE,
            "eligible_for_ready_ranking": False,
            "blockers": blockers,
            "next_step": "Add maintenance line and unresolved CVEs to the OSERA Patch Request Cart (#29 / #42).",
            "evidence_needed": ["osera_coverage_request_submission", "provider_patch_publication"],
            "selected_option": None,
        }

    assert selected_option is not None
    opt_blockers = [str(b) for b in (selected_option.get("blocked_reasons") or []) if str(b).strip()]
    for ob in opt_blockers:
        if ob not in blockers:
            blockers.append(ob)

    if selected_option.get("ready") is not True or blockers:
        evidence_needed: list[str] = []
        for b in blockers:
            if "entitlement" in b:
                evidence_needed.append("active_commercial_entitlement_in_member_overlay")
            elif "evidence" in b or "signature" in b or "promotion" in b or "chain" in b:
                evidence_needed.append("signed_artifact_promotion_and_vex_attestation")
            elif "coverage_commitment" in b or "future" in b:
                evidence_needed.append("published_release_artifact_in_repository")
            else:
                evidence_needed.append(f"remediation_for_{b}")
        return {
            "queue": QUEUE_BLOCKED,
            "eligible_for_ready_ranking": False,
            "blockers": blockers,
            "next_step": f"Resolve blocking condition(s) ({', '.join(blockers)}) or select an alternative provider option.",
            "evidence_needed": sorted(set(evidence_needed)),
            "selected_option": selected_option,
        }

    return {
        "queue": QUEUE_READY_TO_PLAN,
        "eligible_for_ready_ranking": True,
        "blockers": [],
        "next_step": f"Assign owner and schedule adoption of {selected_option.get('replacement_purl')} in change window.",
        "evidence_needed": ["post_deployment_sbom_verification"],
        "selected_option": selected_option,
    }


def _build_comparison_drawer(
    raw_opp: dict[str, Any],
    selected_option: dict[str, Any] | None,
    canonical_adv: Any,
    observed_advisory_ids: list[str],
) -> dict[str, Any]:
    """Build the comparison drawer for upstream, commercial, and OSERA choices including rejection reasons (#27)."""
    choices: list[dict[str, Any]] = []
    sel_id = selected_option.get("patch_id") if isinstance(selected_option, dict) else None

    for opt in raw_opp.get("options") or []:
        if not isinstance(opt, dict):
            continue
        pid = str(opt.get("patch_id") or opt.get("replacement_purl") or "")
        fixed_canon = {canonical_adv(a) for a in (opt.get("fixed_advisories") or []) + (opt.get("aliases") or [])}
        addressed = [a for a in observed_advisory_ids if canonical_adv(a) in fixed_canon]
        remaining = [a for a in observed_advisory_ids if canonical_adv(a) not in fixed_canon]
        for res in opt.get("residual_advisories") or []:
            if canonical_adv(res) not in {canonical_adv(x) for x in remaining}:
                remaining.append(res)

        is_selected = pid == sel_id and bool(opt.get("ready"))
        rejection_reasons: list[str] = []
        if not is_selected:
            if not opt.get("ready"):
                rejection_reasons.extend(opt.get("blocked_reasons") or ["option_not_ready"])
            elif opt.get("rejection_reason"):
                rejection_reasons.append(str(opt["rejection_reason"]))
            elif remaining:
                rejection_reasons.append(f"leaves_residual_advisories:{','.join(remaining)}")
            elif opt.get("effort") == "high":
                rejection_reasons.append("higher_migration_effort_than_selected_same_line_patch")
            else:
                rejection_reasons.append("alternative_ready_option_selected_by_policy")

        choices.append(
            {
                "patch_id": pid,
                "provider": str(opt.get("provider") or "Unknown"),
                "provider_kind": str(opt.get("provider_kind") or "upstream").lower(),
                "replacement_purl": str(opt.get("replacement_purl") or ""),
                "ready": bool(opt.get("ready")),
                "selected": is_selected,
                "addressed_advisories": addressed,
                "remaining_advisories": remaining,
                "estimated_effort": str(opt.get("estimated_effort") or opt.get("effort") or "low"),
                "entitlement_status": str(opt.get("entitlement_status") or "not_required"),
                "evidence_state": str(opt.get("evidence_state") or ("verified" if opt.get("ready") else "blocked")),
                "blocked_reasons": list(opt.get("blocked_reasons") or []),
                "rejection_reasons": rejection_reasons,
            }
        )

    return {
        "opportunity_id": str(raw_opp.get("opportunity_id") or ""),
        "selected_patch_id": sel_id if (selected_option and selected_option.get("ready")) else None,
        "providers_compared": sorted({c["provider_kind"] for c in choices}),
        "choices": choices,
    }


def _build_recipe_guidance(raw_opp: dict[str, Any], selected_option: dict[str, Any] | None) -> dict[str, Any]:
    """Enforce #27 recipe safety: transitive or unknown paths NEVER receive unsafe direct-only OpenRewrite recipes."""
    dep_scope = str(raw_opp.get("dependency_scope") or raw_opp.get("direct_relationship") or "unknown").strip().lower()
    if dep_scope in ("true", "direct"):
        dep_scope = "direct"
    elif dep_scope in ("false", "transitive"):
        dep_scope = "transitive"
    else:
        dep_scope = "unknown"

    action_kind = str(raw_opp.get("action_kind") or "library_patch").strip().lower()
    target_purl = str(selected_option.get("replacement_purl") or "") if isinstance(selected_option, dict) else ""
    parsed = parse_purl(target_purl) if target_purl else {"valid": False, "ecosystem_type": "unknown", "library": "", "version": ""}

    if not selected_option or not selected_option.get("ready"):
        return {
            "dependency_scope": dep_scope,
            "recipe_status": "unavailable_option_not_ready",
            "openrewrite_recipe": None,
            "instructions": "Resolve blockers or request patch coverage before generating build instructions.",
        }

    if dep_scope in ("transitive", "unknown"):
        return {
            "dependency_scope": dep_scope,
            "recipe_status": f"suppressed_{dep_scope}_dependency_path",
            "openrewrite_recipe": None,
            "instructions": (
                f"Direct-dependency OpenRewrite UpgradeDependencyVersion recipe is explicitly suppressed because "
                f"the dependency path is '{dep_scope}'. Pin '{target_purl}' via a dependencyManagement / BOM constraint "
                f"or inspect the introducing root dependency first."
            ),
        }

    if parsed["valid"] and parsed["ecosystem_type"] == "maven" and ":" in parsed["library"]:
        grp, art = parsed["library"].split(":", 1)
        return {
            "dependency_scope": "direct",
            "recipe_status": "supported_direct_maven_recipe",
            "openrewrite_recipe": {
                "type": "specs.openrewrite.org/v1beta/recipe",
                "name": f"org.finos.osera.Upgrade_{grp.replace('.', '_')}_{art.replace('-', '_')}",
                "recipeList": [
                    {
                        "org.openrewrite.maven.UpgradeDependencyVersion": {
                            "groupId": grp,
                            "artifactId": art,
                            "newVersion": parsed["version"],
                        }
                    }
                ],
            },
            "instructions": f"Apply OpenRewrite UpgradeDependencyVersion to update direct dependency {grp}:{art} to {parsed['version']}.",
        }

    return {
        "dependency_scope": dep_scope,
        "recipe_status": "explicit_unsupported_ecosystem_recipe",
        "openrewrite_recipe": None,
        "instructions": f"Automated OpenRewrite recipe generation is not supported for {parsed['ecosystem_type']}; update manifest lockfile to {target_purl}.",
    }


def rank_patch_opportunities(
    fixture_or_payload: dict[str, Any] | Path,
    company_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank patch opportunities using OSERA rules (`rules/prioritisation.yaml`) and company priorities (#26, #27).

    Enforces:
    - OSERA baseline priority (`P0`, `P1`, `P2`) is preserved immutable in `source_priority`.
    - Company policy (`company_policy`) computes `company_priority`, `company_urgency_score`, and explains
      which ranks changed (`rank_changes`) and why without overwriting `source_priority`.
    - Unavailable or blocked opportunities remain visible in `blocked`, `investigate`, or `request_coverage`
      queues with concrete blockers and next steps, and NEVER receive a `ready_rank`.
    - Distinct advisories, affected applications, and exposure instances (`(application_id, canonical_advisory_id)`)
      are labeled separately; unknown data is preserved as `'unknown'`.
    - Keeps `estimated_effort`, `confidence`, and `measured_outcome` separate.
    """
    if isinstance(fixture_or_payload, Path):
        payload = json.loads(fixture_or_payload.read_text(encoding="utf-8"))
    else:
        payload = copy.deepcopy(fixture_or_payload)

    raw_opportunities = payload.get("opportunities") if isinstance(payload.get("opportunities"), list) else []
    rules_cfg = payload.get("osera_rules") if isinstance(payload.get("osera_rules"), dict) else {}
    policy = company_policy if isinstance(company_policy, dict) else (
        payload.get("company_policy") if isinstance(payload.get("company_policy"), dict) else {}
    )

    if not raw_opportunities:
        return {
            "schema_version": OPPORTUNITY_PLANNER_SCHEMA_VERSION,
            "data_completeness_state": "empty_inventory",
            "opportunities": [],
            "queues": {
                QUEUE_READY_TO_PLAN: [],
                QUEUE_BLOCKED: [],
                QUEUE_INVESTIGATE: [],
                QUEUE_REQUEST_COVERAGE: [],
            },
            "rank_changes": [],
            "summary_metrics": {
                "total_opportunities": 0,
                "ready_to_plan_count": 0,
                "blocked_count": 0,
                "investigate_count": 0,
                "request_coverage_count": 0,
                "unique_advisory_count": 0,
                "affected_application_count": 0,
                "exposure_instance_count": 0,
                "unknown_signal_opportunity_count": 0,
            },
        }

    all_adv_records = [
        adv
        for opp in raw_opportunities
        if isinstance(opp, dict)
        for adv in (opp.get("advisories") or [])
        if isinstance(adv, dict)
    ]
    canonical_adv = _canonical_advisory_map(all_adv_records)

    evaluated_opps: list[dict[str, Any]] = []
    all_estate_exposures: set[tuple[str, str]] = set()
    all_unique_advisories: set[str] = set()
    all_affected_apps: set[str] = set()
    has_incomplete_signals = False

    for idx, opp in enumerate(raw_opportunities):
        if not isinstance(opp, dict):
            continue
        opp_id = str(opp.get("opportunity_id") or f"opp-{idx + 1}").strip()
        advisories = [a for a in (opp.get("advisories") or []) if isinstance(a, dict)]
        osera_eval = evaluate_osera_priority(advisories, rules_cfg)
        if osera_eval["unknown_signal_advisories"]:
            has_incomplete_signals = True

        apps = [str(a).strip() for a in (opp.get("affected_applications") or []) if str(a).strip()]
        canonical_adv_ids = sorted(
            {
                canonical_adv(str(a.get("id") or a.get("cve_id") or a.get("advisory_id") or ""))
                for a in advisories
                if str(a.get("id") or a.get("cve_id") or a.get("advisory_id") or "").strip()
            }
        )
        for a in canonical_adv_ids:
            all_unique_advisories.add(a)
        for app in apps:
            all_affected_apps.add(app)

        # Distinct exposure instances: (application_id, canonical_advisory_id)
        raw_exposures = opp.get("exposure_instances")
        exposure_instances: list[str] = []
        if isinstance(raw_exposures, list) and raw_exposures:
            for exp in raw_exposures:
                if isinstance(exp, dict):
                    app_id = str(exp.get("application_id") or "app").strip()
                    adv_id = canonical_adv(str(exp.get("advisory_id") or "").strip())
                    exposure_instances.append(f"{app_id}|{adv_id}")
                    all_estate_exposures.add((app_id, adv_id))
                elif isinstance(exp, str) and "|" in exp:
                    app_id, adv_raw = exp.split("|", 1)
                    adv_id = canonical_adv(adv_raw.strip())
                    exposure_instances.append(f"{app_id.strip()}|{adv_id}")
                    all_estate_exposures.add((app_id.strip(), adv_id))
        else:
            for app_id in apps:
                for adv_id in canonical_adv_ids:
                    exposure_instances.append(f"{app_id}|{adv_id}")
                    all_estate_exposures.add((app_id, adv_id))
        exposure_instances = sorted(set(exposure_instances))

        q_info = _classify_queue_and_next_step(opp)
        sel_opt = q_info["selected_option"]
        drawer = _build_comparison_drawer(opp, sel_opt, canonical_adv, canonical_adv_ids)
        recipe_guidance = _build_recipe_guidance(opp, sel_opt)

        # Determine addressed vs residual exposures for the selected option
        addressed_adv_set: set[str] = set()
        residual_adv_list: list[str] = []
        if sel_opt and q_info["eligible_for_ready_ranking"]:
            fixed_canon = {
                canonical_adv(str(x))
                for x in (sel_opt.get("fixed_advisories") or []) + (sel_opt.get("aliases") or [])
            }
            for cid in canonical_adv_ids:
                if cid in fixed_canon:
                    addressed_adv_set.add(cid)
                else:
                    residual_adv_list.append(cid)
            for res_raw in sel_opt.get("residual_advisories") or []:
                rc = canonical_adv(str(res_raw))
                if rc not in residual_adv_list:
                    residual_adv_list.append(rc)
        else:
            residual_adv_list = list(canonical_adv_ids)

        addressed_exposures = sorted(
            exp for exp in exposure_instances if exp.split("|", 1)[1] in addressed_adv_set
        )
        residual_exposures = sorted(
            exp for exp in exposure_instances if exp.split("|", 1)[1] not in addressed_adv_set
        )

        # Keep estimated_effort, confidence, and measured_outcome strictly separate (#26)
        est_effort = str(
            (sel_opt.get("estimated_effort") if sel_opt else None)
            or opp.get("estimated_effort")
            or "medium"
        ).strip().lower()
        confidence = str(opp.get("confidence") or ("high" if not osera_eval["unknown_signal_advisories"] else "medium")).strip().lower()
        measured_outcome = str(opp.get("measured_outcome") or "not_yet_deployed").strip().lower()

        # Baseline OSERA score for deterministic baseline ordering
        osera_prio = osera_eval["priority"]
        osera_base_score = (
            (300 if osera_prio == "P0" else 200 if osera_prio == "P1" else 100)
            + len(addressed_exposures) * 5
            - EFFORT_ORDER.get(est_effort, 2)
        )

        # Company priority overlay calculation (never overwrites source_priority!)
        app_criticality = str(opp.get("business_criticality") or "medium").strip().lower()
        internet_exposed = bool(opp.get("internet_exposed", False))
        sla_days_remaining = opp.get("sla_days_remaining")
        change_window = str(opp.get("change_window") or "standard_weekly").strip()

        company_reasons: list[str] = []
        company_delta = 0
        if policy:
            crit_weights = policy.get("criticality_weights") if isinstance(policy.get("criticality_weights"), dict) else CRITICALITY_WEIGHT
            w = int(crit_weights.get(app_criticality, CRITICALITY_WEIGHT.get(app_criticality, 0)))
            if w > 0:
                company_delta += w
                company_reasons.append(f"business_criticality={app_criticality} (+{w})")
            if internet_exposed and policy.get("boost_internet_exposed", True):
                boost = int(policy.get("internet_exposure_boost", 45))
                company_delta += boost
                company_reasons.append(f"internet_exposed=true (+{boost})")
            if isinstance(sla_days_remaining, (int, float)) and sla_days_remaining <= int(policy.get("urgent_sla_threshold_days", 7)):
                sla_boost = int(policy.get("urgent_sla_boost", 60))
                company_delta += sla_boost
                company_reasons.append(f"sla_days_remaining={sla_days_remaining}d (+{sla_boost})")
            if change_window in (policy.get("frozen_change_windows") or []):
                penalty = int(policy.get("change_freeze_penalty", 50))
                company_delta -= penalty
                company_reasons.append(f"change_window={change_window} constrained (-{penalty})")

        company_score = osera_base_score + company_delta
        if company_score >= 280:
            company_priority = "P0"
        elif company_score >= 190:
            company_priority = "P1"
        else:
            company_priority = "P2"

        evaluated_opps.append(
            {
                "opportunity_id": opp_id,
                "Scenario": str(opp.get("scenario") or opp_id),
                "action_kind": str(opp.get("action_kind") or "library_patch"),
                "library": str(opp.get("library") or ""),
                "deployed_purl": str(opp.get("deployed_purl") or ""),
                "framework_or_runtime": str(opp.get("framework_or_runtime") or "jvm-standard"),
                "owner": str(opp.get("owner") or "unassigned"),
                "change_window": change_window,
                "business_criticality": app_criticality,
                "internet_exposed": internet_exposed,
                "sla_days_remaining": sla_days_remaining if sla_days_remaining is not None else "unknown",
                "queue": q_info["queue"],
                "eligible_for_ready_ranking": q_info["eligible_for_ready_ranking"],
                "source_priority": osera_prio,
                "source_priority_rule": osera_eval["rule_id"],
                "source_priority_reason": osera_eval["reason"],
                "osera_rules_version": osera_eval["rules_version"],
                "company_priority": company_priority,
                "company_priority_reasons": company_reasons,
                "osera_baseline_score": osera_base_score,
                "company_urgency_score": company_score,
                "osera_baseline_rank": None,
                "ready_rank": None,
                "rank_changed_by_company_policy": False,
                "rank_change_explanation": None,
                "target_purl": str(sel_opt.get("replacement_purl") or "") if sel_opt else None,
                "provider": str(sel_opt.get("provider") or "None") if sel_opt else None,
                "provider_kind": str(sel_opt.get("provider_kind") or "none") if sel_opt else None,
                "entitlement_status": str(sel_opt.get("entitlement_status") or "unknown") if sel_opt else "not_applicable",
                "evidence_state": str((sel_opt.get("evidence_state") if sel_opt else None) or ("verified" if q_info["eligible_for_ready_ranking"] else "blocked")),
                "distinct_counts": {
                    "unique_advisory_count": len(canonical_adv_ids),
                    "affected_application_count": len(apps),
                    "exposure_instance_count": len(exposure_instances),
                    "addressed_exposure_instance_count": len(addressed_exposures),
                    "residual_exposure_instance_count": len(residual_exposures),
                },
                "affected_applications": apps,
                "unique_advisories": canonical_adv_ids,
                "addressed_advisories": sorted(addressed_adv_set),
                "residual_advisories": residual_adv_list,
                "exposure_instances": exposure_instances,
                "addressed_exposure_instances": addressed_exposures,
                "residual_exposure_instances": residual_exposures,
                "signal_summary": osera_eval["signal_summary"],
                "unknown_signal_advisories": osera_eval["unknown_signal_advisories"],
                "estimated_effort": est_effort,
                "confidence": confidence,
                "measured_outcome": measured_outcome,
                "blockers": q_info["blockers"],
                "next_step": q_info["next_step"],
                "evidence_needed": q_info["evidence_needed"],
                "recipe_guidance": recipe_guidance,
                "comparison_drawer": drawer,
                "rollback_target": str(opp.get("deployed_purl") or ""),
                "required_validation": list(
                    opp.get("required_validation")
                    or ["verify_artifact_digest_and_vex", "run_integration_test_suite", "re_scan_deployed_sbom"]
                ),
            }
        )

    # Rank ONLY ready_to_plan opportunities! Blocked/Investigate/Request coverage NEVER rank as ready (#26).
    ready_opps = [o for o in evaluated_opps if o["eligible_for_ready_ranking"]]
    baseline_sorted = sorted(
        ready_opps,
        key=lambda o: (
            PRIORITY_ORDER.get(o["source_priority"], 9),
            -o["osera_baseline_score"],
            o["opportunity_id"],
        ),
    )
    for r_idx, o in enumerate(baseline_sorted, start=1):
        o["osera_baseline_rank"] = r_idx

    company_sorted = sorted(
        ready_opps,
        key=lambda o: (
            PRIORITY_ORDER.get(o["company_priority"], 9),
            -o["company_urgency_score"],
            o["opportunity_id"],
        ),
    )
    rank_changes: list[dict[str, Any]] = []
    for c_idx, o in enumerate(company_sorted, start=1):
        o["ready_rank"] = c_idx
        if o["osera_baseline_rank"] != c_idx:
            o["rank_changed_by_company_policy"] = True
            why = "; ".join(o["company_priority_reasons"]) or "Relative score shift from peer company urgency"
            o["rank_change_explanation"] = (
                f"Moved from OSERA baseline rank #{o['osera_baseline_rank']} ({o['source_priority']}) "
                f"to company rank #{c_idx} ({o['company_priority']}): {why}"
            )
            rank_changes.append(
                {
                    "opportunity_id": o["opportunity_id"],
                    "library": o["library"],
                    "source_priority": o["source_priority"],
                    "company_priority": o["company_priority"],
                    "osera_baseline_rank": o["osera_baseline_rank"],
                    "company_ready_rank": c_idx,
                    "why": o["rank_change_explanation"],
                }
            )
        else:
            o["rank_change_explanation"] = (
                f"Retained rank #{c_idx} (source_priority={o['source_priority']}, company_priority={o['company_priority']})"
            )

    # Order full list: ready_to_plan (by ready_rank), then blocked, investigate, request_coverage
    non_ready_order = {QUEUE_BLOCKED: 1, QUEUE_INVESTIGATE: 2, QUEUE_REQUEST_COVERAGE: 3}
    non_ready_opps = sorted(
        [o for o in evaluated_opps if not o["eligible_for_ready_ranking"]],
        key=lambda o: (
            non_ready_order.get(o["queue"], 9),
            PRIORITY_ORDER.get(o["source_priority"], 9),
            o["opportunity_id"],
        ),
    )
    ordered_all = company_sorted + non_ready_opps

    queues = {
        QUEUE_READY_TO_PLAN: [o for o in ordered_all if o["queue"] == QUEUE_READY_TO_PLAN],
        QUEUE_BLOCKED: [o for o in ordered_all if o["queue"] == QUEUE_BLOCKED],
        QUEUE_INVESTIGATE: [o for o in ordered_all if o["queue"] == QUEUE_INVESTIGATE],
        QUEUE_REQUEST_COVERAGE: [o for o in ordered_all if o["queue"] == QUEUE_REQUEST_COVERAGE],
    }

    return {
        "schema_version": OPPORTUNITY_PLANNER_SCHEMA_VERSION,
        "data_completeness_state": "incomplete_signals" if has_incomplete_signals else "complete",
        "opportunities": ordered_all,
        "queues": queues,
        "rank_changes": rank_changes,
        "summary_metrics": {
            "total_opportunities": len(ordered_all),
            "ready_to_plan_count": len(queues[QUEUE_READY_TO_PLAN]),
            "blocked_count": len(queues[QUEUE_BLOCKED]),
            "investigate_count": len(queues[QUEUE_INVESTIGATE]),
            "request_coverage_count": len(queues[QUEUE_REQUEST_COVERAGE]),
            "unique_advisory_count": len(all_unique_advisories),
            "affected_application_count": len(all_affected_apps),
            "exposure_instance_count": len(all_estate_exposures),
            "unknown_signal_opportunity_count": sum(1 for o in ordered_all if o["unknown_signal_advisories"]),
        },
    }


def assemble_portfolio_plan(
    ranked_result: dict[str, Any],
    *,
    selected_opportunity_ids: list[str] | None = None,
    owner: str | None = None,
    framework_or_runtime: str | None = None,
    change_window: str | None = None,
) -> dict[str, Any]:
    """Assemble a portfolio plan with deduplicated incremental benefit across overlapping library and framework/BOM actions (#26, #27).

    Recomputes portfolio benefit as a set union of addressed exposure instances (`application_id|advisory_id`)
    so a framework/BOM upgrade and an individual library patch NEVER claim the same exposure reduction twice.
    """
    ready_candidates = ranked_result.get("queues", {}).get(QUEUE_READY_TO_PLAN) or [
        o for o in (ranked_result.get("opportunities") or []) if o.get("eligible_for_ready_ranking")
    ]

    selected: list[dict[str, Any]] = []
    for opp in ready_candidates:
        if selected_opportunity_ids is not None and opp["opportunity_id"] not in selected_opportunity_ids:
            continue
        if owner and opp["owner"].lower() != owner.lower():
            continue
        if framework_or_runtime and opp["framework_or_runtime"].lower() != framework_or_runtime.lower():
            continue
        if change_window and opp["change_window"].lower() != change_window.lower():
            continue
        selected.append(opp)

    cumulative_addressed: set[str] = set()
    all_scope_exposures: set[str] = set()
    for opp in selected:
        all_scope_exposures.update(opp.get("exposure_instances") or [])

    incremental_rows: list[dict[str, Any]] = []
    raw_sum_claimed = 0

    for step_idx, opp in enumerate(selected, start=1):
        claimed = set(opp.get("addressed_exposure_instances") or [])
        raw_sum_claimed += len(claimed)
        newly_addressed = sorted(claimed - cumulative_addressed)
        already_covered = sorted(claimed & cumulative_addressed)
        cumulative_addressed.update(claimed)

        incremental_rows.append(
            {
                "step": step_idx,
                "opportunity_id": opp["opportunity_id"],
                "action_kind": opp["action_kind"],
                "library": opp["library"],
                "target_purl": opp["target_purl"],
                "provider": opp["provider"],
                "owner": opp["owner"],
                "change_window": opp["change_window"],
                "standalone_claimed_exposure_reduction": len(claimed),
                "incremental_exposure_reduction": len(newly_addressed),
                "overlapping_exposure_instances_deduplicated": already_covered,
                "newly_addressed_exposure_instances": newly_addressed,
                "residual_exposure_instances_on_component": opp["residual_exposure_instances"],
                "estimated_effort": opp["estimated_effort"],
                "confidence": opp["confidence"],
                "measured_outcome": opp["measured_outcome"],
            }
        )

    portfolio_residual = sorted(all_scope_exposures - cumulative_addressed)
    affected_apps = sorted({exp.split("|", 1)[0] for exp in all_scope_exposures})
    addressed_advisories = sorted({exp.split("|", 1)[1] for exp in cumulative_addressed})
    residual_advisories = sorted({exp.split("|", 1)[1] for exp in portfolio_residual})

    return {
        "schema_version": OPPORTUNITY_PLANNER_SCHEMA_VERSION,
        "filters": {
            "owner": owner,
            "framework_or_runtime": framework_or_runtime,
            "change_window": change_window,
            "selected_opportunity_ids": selected_opportunity_ids,
        },
        "selected_count": len(selected),
        "incremental_actions": incremental_rows,
        "portfolio_metrics": {
            "affected_application_count": len(affected_apps),
            "total_scope_exposure_instances": len(all_scope_exposures),
            "naive_unioned_claim_sum": raw_sum_claimed,
            "deduplicated_addressed_exposure_instances": len(cumulative_addressed),
            "duplicate_overlap_prevented": raw_sum_claimed - len(cumulative_addressed),
            "residual_exposure_instance_count": len(portfolio_residual),
            "addressed_unique_advisories": addressed_advisories,
            "residual_unique_advisories": residual_advisories,
        },
        "deduplicated_addressed_exposures": sorted(cumulative_addressed),
        "residual_exposures": portfolio_residual,
    }


def export_owner_change_package(
    ranked_result: dict[str, Any],
    portfolio_plan: dict[str, Any],
) -> dict[str, Any]:
    """Export an owner-ready change package with coordinates, dependencies, evidence, instructions, validation, and rollback (#27)."""
    opp_by_id = {o["opportunity_id"]: o for o in (ranked_result.get("opportunities") or [])}
    packages: list[dict[str, Any]] = []

    for item in portfolio_plan.get("incremental_actions") or []:
        opp = opp_by_id.get(item["opportunity_id"], {})
        drawer = opp.get("comparison_drawer") or {}
        selected_choice = next((c for c in (drawer.get("choices") or []) if c.get("selected")), {})
        rejected_choices = [
            {
                "patch_id": c["patch_id"],
                "provider": c["provider"],
                "replacement_purl": c["replacement_purl"],
                "rejection_reasons": c["rejection_reasons"],
            }
            for c in (drawer.get("choices") or [])
            if not c.get("selected")
        ]

        packages.append(
            {
                "opportunity_id": opp.get("opportunity_id"),
                "owner": opp.get("owner"),
                "change_window": opp.get("change_window"),
                "framework_or_runtime": opp.get("framework_or_runtime"),
                "action_kind": opp.get("action_kind"),
                "source_coordinate": opp.get("deployed_purl"),
                "target_coordinate": opp.get("target_purl"),
                "provider": opp.get("provider"),
                "provider_kind": opp.get("provider_kind"),
                "entitlement_status": opp.get("entitlement_status"),
                "evidence_state": opp.get("evidence_state"),
                "source_priority": opp.get("source_priority"),
                "company_priority": opp.get("company_priority"),
                "affected_applications": opp.get("affected_applications"),
                "incremental_exposure_reduction": item["incremental_exposure_reduction"],
                "residual_advisories": opp.get("residual_advisories"),
                "implementation_instructions": opp.get("recipe_guidance", {}).get("instructions"),
                "recipe_status": opp.get("recipe_guidance", {}).get("recipe_status"),
                "openrewrite_recipe": opp.get("recipe_guidance", {}).get("openrewrite_recipe"),
                "required_validation": opp.get("required_validation"),
                "rollback_target": opp.get("rollback_target"),
                "selected_option_details": selected_choice,
                "rejected_alternatives": rejected_choices,
            }
        )

    return {
        "schema_version": CHANGE_PACKAGE_SCHEMA_VERSION,
        "portfolio_metrics": portfolio_plan["portfolio_metrics"],
        "change_packages": packages,
    }

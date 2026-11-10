import json
import unittest
from pathlib import Path

from patch_opportunity_planner import (
    QUEUE_BLOCKED,
    QUEUE_INVESTIGATE,
    QUEUE_READY_TO_PLAN,
    QUEUE_REQUEST_COVERAGE,
    assemble_portfolio_plan,
    detect_plan_snapshot_drift,
    evaluate_osera_priority,
    export_owner_change_package,
    export_owner_change_package_csv,
    export_owner_change_package_cyclonedx,
    export_owner_change_package_markdown,
    rank_patch_opportunities,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT_DIR / "data" / "fixtures" / "patch-opportunity-planner" / "representative-estate-opportunities.json"


def test_osera_ordered_inclusion_p0_p1_p2_kev_and_medium_with_signal():
    ranked = rank_patch_opportunities(FIXTURE_PATH, company_policy={})
    by_id = {o["opportunity_id"]: o for o in ranked["opportunities"]}

    # P0 KEV rule
    spring_kev = by_id["opp-osera-spring-web-kev"]
    assert spring_kev["source_priority"] == "P0"
    assert spring_kev["source_priority_rule"] == "OSERA-P0-KEV"
    assert spring_kev["signal_summary"]["max_epss_probability"] == 0.42
    assert spring_kev["signal_summary"]["max_epss_percentile"] == 0.97

    # P1 High CVSS without P0 trigger
    tomcat_core = by_id["opp-upstream-tomcat-core"]
    assert tomcat_core["source_priority"] == "P1"
    assert tomcat_core["source_priority_rule"] == "OSERA-P1-HIGH"

    # P1 Medium-with-signal case (CVSS 6.5 + EPSS percentile 0.94 / PoC exploit maturity)
    tomcat_bom = by_id["opp-commercial-tomcat-bom-medium-signal"]
    assert tomcat_bom["source_priority"] == "P1"
    assert tomcat_bom["source_priority_rule"] == "OSERA-P1-MEDIUM-WITH-SIGNAL"

    # P2 baseline + unknown CVSS/EPSS preserved as 'unknown' (never 0.0 or zero risk!)
    jackson_p2 = by_id["opp-baseline-p2-unknown-signal"]
    assert jackson_p2["source_priority"] == "P2"
    assert "GHSA-unknown-cvss-epss" in jackson_p2["unknown_signal_advisories"]
    prov_by_adv = {p["advisory_id"]: p for p in jackson_p2["signal_summary"]["cvss_provenance"]}
    assert prov_by_adv["GHSA-unknown-cvss-epss"]["cvss_score"] == "unknown"
    assert prov_by_adv["GHSA-unknown-cvss-epss"]["epss_probability"] == "unknown"
    assert prov_by_adv["GHSA-unknown-cvss-epss"]["epss_percentile"] == "unknown"


def test_company_policy_explains_rank_changes_without_overwriting_source_priority():
    raw = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    ranked_with_policy = rank_patch_opportunities(raw)
    by_id = {o["opportunity_id"]: o for o in ranked_with_policy["opportunities"]}

    # tomcat-bom has source_priority P1, but under company policy (tier_1_critical + internet_exposed + 2d SLA)
    # its company_priority becomes P0 and it moves from OSERA baseline rank #2 to company ready_rank #1!
    bom_opp = by_id["opp-commercial-tomcat-bom-medium-signal"]
    assert bom_opp["source_priority"] == "P1"  # Never overwritten!
    assert bom_opp["company_priority"] == "P0"
    assert bom_opp["osera_baseline_rank"] == 2
    assert bom_opp["ready_rank"] == 1
    assert bom_opp["rank_changed_by_company_policy"] is True
    assert "business_criticality=tier_1_critical" in bom_opp["rank_change_explanation"]
    assert "internet_exposed=true" in bom_opp["rank_change_explanation"]
    assert "sla_days_remaining=2d" in bom_opp["rank_change_explanation"]
    assert len(ranked_with_policy["rank_changes"]) >= 2


def test_unavailable_blocked_investigate_and_unmet_coverage_cannot_rank_as_ready():
    ranked = rank_patch_opportunities(FIXTURE_PATH)
    by_id = {o["opportunity_id"]: o for o in ranked["opportunities"]}

    # Ready queue contains only the 4 eligible opportunities
    assert [o["opportunity_id"] for o in ranked["queues"][QUEUE_READY_TO_PLAN]] == [
        "opp-commercial-tomcat-bom-medium-signal",
        "opp-osera-spring-web-kev",
        "opp-upstream-tomcat-core",
        "opp-baseline-p2-unknown-signal",
    ]

    # Blocked evidence row (Critical CVSS 9.1!) remains visible in blocked queue with concrete next_step & evidence_needed
    blocked_netty = by_id["opp-blocked-netty-evidence"]
    assert blocked_netty["queue"] == QUEUE_BLOCKED
    assert blocked_netty["eligible_for_ready_ranking"] is False
    assert blocked_netty["ready_rank"] is None
    assert "unverified_artifact_promotion_signature" in blocked_netty["blockers"]
    assert blocked_netty["next_step"]
    assert "signed_artifact_promotion_and_vex_attestation" in blocked_netty["evidence_needed"]

    # Ambiguous identity row in investigate queue
    ambig_guava = by_id["opp-ambiguous-guava-identity"]
    assert ambig_guava["queue"] == QUEUE_INVESTIGATE
    assert ambig_guava["eligible_for_ready_ranking"] is False
    assert ambig_guava["ready_rank"] is None
    assert "build_sbom_with_exact_purl" in ambig_guava["evidence_needed"]

    # Unmet coverage row in request_coverage queue
    unmet_io = by_id["opp-unmet-coverage-commons-io"]
    assert unmet_io["queue"] == QUEUE_REQUEST_COVERAGE
    assert unmet_io["eligible_for_ready_ranking"] is False
    assert unmet_io["ready_rank"] is None
    assert "osera_coverage_request_submission" in unmet_io["evidence_needed"]


def test_overlapping_library_and_framework_bom_fixes_receive_only_incremental_portfolio_credit():
    ranked = rank_patch_opportunities(FIXTURE_PATH)

    # Select team-payments portfolio containing both opp-commercial-tomcat-bom-medium-signal (addresses 4 exposures
    # including payments-gateway|CVE-2024-24549 and treasury-engine|CVE-2024-24549) and opp-upstream-tomcat-core
    # (which also claims those exact 2 CVE-2024-24549 exposures!)
    portfolio = assemble_portfolio_plan(ranked, owner="team-payments")
    assert portfolio["selected_count"] == 3

    actions_by_id = {a["opportunity_id"]: a for a in portfolio["incremental_actions"]}
    bom_act = actions_by_id["opp-commercial-tomcat-bom-medium-signal"]
    core_act = actions_by_id["opp-upstream-tomcat-core"]

    assert bom_act["standalone_claimed_exposure_reduction"] == 4
    assert bom_act["incremental_exposure_reduction"] == 4

    # Because tomcat-bom already addressed CVE-2024-24549 on both apps, tomcat-core gets 0 incremental credit!
    assert core_act["standalone_claimed_exposure_reduction"] == 2
    assert core_act["incremental_exposure_reduction"] == 0
    assert core_act["overlapping_exposure_instances_deduplicated"] == [
        "payments-gateway|CVE-2024-24549",
        "treasury-engine|CVE-2024-24549",
    ]
    # And residual CVE-2024-23672 remains visible in portfolio residual exposures
    assert "CVE-2024-23672" in portfolio["portfolio_metrics"]["residual_unique_advisories"]
    assert portfolio["portfolio_metrics"]["duplicate_overlap_prevented"] == 2


def test_recipe_suppression_comparison_drawer_owner_export_and_empty_data_states():
    ranked = rank_patch_opportunities(FIXTURE_PATH)
    by_id = {o["opportunity_id"]: o for o in ranked["opportunities"]}

    # Direct dependency receives OpenRewrite recipe; transitive and unknown paths have recipes explicitly suppressed
    assert by_id["opp-osera-spring-web-kev"]["recipe_guidance"]["recipe_status"] == "supported_direct_maven_recipe"
    assert by_id["opp-osera-spring-web-kev"]["recipe_guidance"]["openrewrite_recipe"] is not None

    assert by_id["opp-upstream-tomcat-core"]["recipe_guidance"]["recipe_status"] == "suppressed_transitive_dependency_path"
    assert by_id["opp-upstream-tomcat-core"]["recipe_guidance"]["openrewrite_recipe"] is None

    assert by_id["opp-ambiguous-guava-identity"]["recipe_guidance"]["openrewrite_recipe"] is None

    # Comparison drawer shows upstream, commercial, and OSERA choices and why alternatives were rejected
    drawer = by_id["opp-osera-spring-web-kev"]["comparison_drawer"]
    assert drawer["providers_compared"] == ["commercial", "osera", "upstream"]
    choices_by_kind = {c["provider_kind"]: c for c in drawer["choices"]}
    assert choices_by_kind["osera"]["selected"] is True
    assert "leaves_residual_advisories:CVE-2024-22259" in choices_by_kind["upstream"]["rejection_reasons"]
    assert "missing_commercial_entitlement" in choices_by_kind["commercial"]["rejection_reasons"]

    # Export owner-ready change package
    portfolio = assemble_portfolio_plan(ranked, owner="team-payments")
    pkg = export_owner_change_package(ranked, portfolio)
    assert pkg["schema_version"] == "osera-owner-change-package/v1"
    assert len(pkg["change_packages"]) == 3
    first_pkg = pkg["change_packages"][0]
    assert first_pkg["rollback_target"]
    assert first_pkg["required_validation"]
    assert first_pkg["target_coordinate"]

    # Empty inventory state remains distinguishable from 'complete' or 'incomplete_signals'
    empty_res = rank_patch_opportunities({"opportunities": []})
    assert empty_res["data_completeness_state"] == "empty_inventory"
    assert ranked["data_completeness_state"] == "incomplete_signals"


def test_pipe_delimited_app_ids_independent_occurrences_target_residuals_and_drift_exports():
    """Verify pipe-containing app IDs, independent occurrences, target-version residuals, drift detection, and exports (#26, #27)."""
    payload = {
        "opportunities": [
            {
                "opportunity_id": "opp-spring-module-a",
                "action_kind": "library_patch",
                "library": "org.springframework:spring-web",
                "deployed_purl": "pkg:maven/org.springframework/spring-web@5.3.18",
                "framework_or_runtime": "spring-5.3",
                "owner": "team-payments",
                "change_window": "standard_weekly",
                "identity_status": "confirmed",
                "dependency_scope": "direct",
                "affected_applications": ["github|acme|payments|main"],
                "advisories": [{"id": "CVE-2024-22243", "kev": True, "cvss_score": 8.1, "epss_probability": 0.42}],
                "options": [
                    {
                        "patch_id": "spring-5.3.18-osera-1",
                        "provider": "OSERA",
                        "provider_kind": "osera",
                        "replacement_purl": "pkg:maven/org.springframework/spring-web@5.3.18-osera-00001",
                        "ready": True,
                        "fixed_advisories": ["CVE-2024-22243"],
                        "residual_advisories": ["CVE-2024-99999"],
                    }
                ],
            },
            {
                "opportunity_id": "opp-spring-module-b",
                "action_kind": "library_patch",
                "library": "org.springframework:spring-web",
                "deployed_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
                "framework_or_runtime": "spring-5.3",
                "owner": "team-payments",
                "change_window": "standard_weekly",
                "identity_status": "confirmed",
                "dependency_scope": "direct",
                "affected_applications": ["github|acme|payments|main"],
                "advisories": [{"id": "CVE-2024-22243", "kev": True, "cvss_score": 8.1, "epss_probability": 0.42}],
                "options": [
                    {
                        "patch_id": "spring-5.3.20-osera-1",
                        "provider": "OSERA",
                        "provider_kind": "osera",
                        "replacement_purl": "pkg:maven/org.springframework/spring-web@5.3.20-osera-00001",
                        "ready": True,
                        "fixed_advisories": ["CVE-2024-22243"],
                        "residual_advisories": [],
                    }
                ],
            },
        ]
    }
    ranked = rank_patch_opportunities(payload)
    assert ranked["summary_metrics"]["affected_application_count"] == 1
    assert ranked["summary_metrics"]["exposure_instance_count"] == 2

    by_id = {o["opportunity_id"]: o for o in ranked["opportunities"]}
    assert len(by_id["opp-spring-module-a"]["addressed_exposure_instances"]) == 1
    assert any(e.endswith("|CVE-2024-99999") for e in by_id["opp-spring-module-a"]["residual_exposure_instances"])

    # Selecting only module-a leaves module-b's CVE-2024-22243 unaddressed AND reports target-version CVE-2024-99999 residual
    full_plan = assemble_portfolio_plan(ranked)
    actions_by_id = {a["opportunity_id"]: a for a in full_plan["incremental_actions"]}
    assert actions_by_id["opp-spring-module-a"]["incremental_exposure_reduction"] == 1
    assert actions_by_id["opp-spring-module-b"]["incremental_exposure_reduction"] == 1
    assert full_plan["portfolio_metrics"]["deduplicated_addressed_exposure_instances"] == 2
    assert full_plan["portfolio_metrics"]["duplicate_overlap_prevented"] == 0
    assert full_plan["portfolio_metrics"]["affected_application_count"] == 1
    assert "CVE-2024-99999" in full_plan["portfolio_metrics"]["residual_unique_advisories"]
    assert full_plan["portfolio_metrics"]["residual_exposure_instance_count"] == 1

    # Export Markdown, CSV, CycloneDX and verify snapshot drift detection
    pkg = export_owner_change_package(ranked, full_plan)
    assert pkg["baseline_hashes"]["plan_baseline_hash"].startswith("sha256:")
    assert "# OSERA Owner-Ready Patch Change Package" in pkg["exports"]["markdown"]
    assert "opp-spring-module-a" in export_owner_change_package_csv(pkg)
    cdx = export_owner_change_package_cyclonedx(pkg)
    assert cdx["bomFormat"] == "CycloneDX"
    assert any(v["id"] == "CVE-2024-99999" and v["analysis"]["state"] == "exploitable" for v in cdx["vulnerabilities"])

    no_drift = detect_plan_snapshot_drift(pkg, ranked)
    assert no_drift["drifted"] is False

    mutated_payload = json.loads(json.dumps(payload))
    mutated_payload["opportunities"][0]["options"][0]["ready"] = False
    mutated_payload["opportunities"][0]["options"][0]["blocked_reasons"] = ["withdrawn_artifact"]
    drifted_ranked = rank_patch_opportunities(mutated_payload)
    drift_report = detect_plan_snapshot_drift(pkg, drifted_ranked)
    assert drift_report["drifted"] is True
    assert drift_report["catalog_options_changed"] is True
    assert any(d["kind"] == "target_option_withdrawn_or_blocked" for d in drift_report["drift_events"])


def test_assessment_scope_independence_and_distinct_components_in_same_deployment():
    """Verify assessment scope stays independent of selected actions and distinct components in one deployment never collide (#26, #27)."""
    payload = {
        "opportunities": [
            {
                "opportunity_id": "opp-comp-a-prod-eu",
                "action_kind": "library_patch",
                "library": "org.example:comp-a",
                "deployed_purl": "pkg:maven/org.example/comp-a@1.0.0",
                "deployment_id": "prod-eu",
                "framework_or_runtime": "spring-6",
                "owner": "team-payments",
                "change_window": "standard_weekly",
                "identity_status": "confirmed",
                "dependency_scope": "direct",
                "affected_applications": ["payments-app"],
                "advisories": [{"id": "CVE-2026-1111", "kev": False, "cvss_score": 8.2}],
                "options": [
                    {
                        "patch_id": "comp-a-1.0.1",
                        "provider": "Upstream",
                        "provider_kind": "upstream",
                        "replacement_purl": "pkg:maven/org.example/comp-a@1.0.1",
                        "ready": True,
                        "fixed_advisories": ["CVE-2026-1111"],
                        "residual_advisories": [],
                    }
                ],
            },
            {
                "opportunity_id": "opp-comp-b-prod-eu",
                "action_kind": "library_patch",
                "library": "org.example:comp-b",
                "deployed_purl": "pkg:maven/org.example/comp-b@2.0.0",
                "deployment_id": "prod-eu",
                "framework_or_runtime": "spring-6",
                "owner": "team-payments",
                "change_window": "standard_weekly",
                "identity_status": "confirmed",
                "dependency_scope": "direct",
                "affected_applications": ["payments-app"],
                "advisories": [{"id": "CVE-2026-1111", "kev": False, "cvss_score": 8.2}],
                "options": [
                    {
                        "patch_id": "comp-b-2.0.1",
                        "provider": "Upstream",
                        "provider_kind": "upstream",
                        "replacement_purl": "pkg:maven/org.example/comp-b@2.0.1",
                        "ready": True,
                        "fixed_advisories": ["CVE-2026-1111"],
                        "residual_advisories": [],
                    }
                ],
            },
            {
                "opportunity_id": "opp-unpatchable-comp-c-prod-eu",
                "action_kind": "library_patch",
                "library": "org.example:comp-c",
                "deployed_purl": "pkg:maven/org.example/comp-c@3.0.0",
                "deployment_id": "prod-eu",
                "framework_or_runtime": "spring-6",
                "owner": "team-payments",
                "change_window": "standard_weekly",
                "identity_status": "confirmed",
                "dependency_scope": "direct",
                "affected_applications": ["payments-app"],
                "advisories": [{"id": "CVE-2026-2222", "kev": False, "cvss_score": 7.5}],
                "options": [],
            },
        ]
    }
    ranked = rank_patch_opportunities(payload)
    # 3 distinct component exposures in prod-eu (comp-a|CVE-2026-1111, comp-b|CVE-2026-1111, comp-c|CVE-2026-2222)
    assert ranked["summary_metrics"]["exposure_instance_count"] == 3

    # Selecting ONLY opp-comp-a-prod-eu must keep comp-b AND unpatchable comp-c in the assessment scope as residual!
    partial_plan = assemble_portfolio_plan(ranked, selected_opportunity_ids=["opp-comp-a-prod-eu"])
    assert partial_plan["selected_count"] == 1
    assert partial_plan["portfolio_metrics"]["total_scope_exposure_instances"] == 3
    assert partial_plan["portfolio_metrics"]["deduplicated_addressed_exposure_instances"] == 1
    assert partial_plan["portfolio_metrics"]["residual_exposure_instance_count"] == 2
    assert set(partial_plan["portfolio_metrics"]["residual_unique_advisories"]) == {
        "CVE-2026-1111",
        "CVE-2026-2222",
    }

    # Selecting all ready opportunities addresses comp-a and comp-b (2 distinct exposures) while unpatchable comp-c remains residual
    ready_plan = assemble_portfolio_plan(ranked)
    assert ready_plan["selected_count"] == 2
    assert ready_plan["portfolio_metrics"]["total_scope_exposure_instances"] == 3
    assert ready_plan["portfolio_metrics"]["deduplicated_addressed_exposure_instances"] == 2
    assert ready_plan["portfolio_metrics"]["duplicate_overlap_prevented"] == 0
    assert ready_plan["portfolio_metrics"]["residual_exposure_instance_count"] == 1
    assert ready_plan["portfolio_metrics"]["residual_unique_advisories"] == ["CVE-2026-2222"]


class PatchOpportunityPlannerTestCase(unittest.TestCase):
    def test_all(self):
        test_osera_ordered_inclusion_p0_p1_p2_kev_and_medium_with_signal()
        test_company_policy_explains_rank_changes_without_overwriting_source_priority()
        test_unavailable_blocked_investigate_and_unmet_coverage_cannot_rank_as_ready()
        test_overlapping_library_and_framework_bom_fixes_receive_only_incremental_portfolio_credit()
        test_recipe_suppression_comparison_drawer_owner_export_and_empty_data_states()
        test_pipe_delimited_app_ids_independent_occurrences_target_residuals_and_drift_exports()
        test_assessment_scope_independence_and_distinct_components_in_same_deployment()


if __name__ == "__main__":
    unittest.main()

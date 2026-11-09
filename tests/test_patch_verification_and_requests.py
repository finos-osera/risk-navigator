import json
import unittest
from pathlib import Path

from patch_verification_and_requests import (
    build_privacy_preserving_request_export,
    deduplicate_authenticated_intake_submissions,
    reconcile_patch_plans_with_observations,
    validate_and_normalize_coverage_request,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT_DIR / "data" / "fixtures" / "patch-verification-requests"
RECONCILIATION_FIXTURE_PATH = FIXTURE_DIR / "patch-plan-reconciliation-fixture.json"
REQUEST_INTAKE_FIXTURE_PATH = FIXTURE_DIR / "coverage-request-and-intake-fixture.json"


def test_closed_ticket_recipe_or_osera_issue_without_deployment_cannot_verify_remediation():
    report = reconcile_patch_plans_with_observations(RECONCILIATION_FIXTURE_PATH)
    by_id = {p["plan_id"]: p for p in report["plans"]}

    # 1. Full rollout with exact digest & passed validation reaches 'verified'
    verified_plan = by_id["plan-verified-full-rollout"]
    assert verified_plan["reconciled_stage"] == "verified"
    assert len(verified_plan["observed_remediated_exposures"]) == 4
    assert verified_plan["residual_exposures"] == []

    # 2. Closed ticket + closed OSERA issue + generated recipe without deployment evidence CANNOT mark exposure verified!
    closed_ticket = by_id["plan-closed-ticket-no-deployment"]
    assert closed_ticket["non_deployment_signals_ignored"]["ticket_status"] == "closed"
    assert closed_ticket["non_deployment_signals_ignored"]["osera_issue_status"] == "closed"
    assert closed_ticket["non_deployment_signals_ignored"]["recipe_generated"] is True
    assert closed_ticket["reconciled_stage"] == "planned"
    assert closed_ticket["observed_remediated_exposures"] == []
    assert closed_ticket["residual_exposures"] == ["treasury-engine-closed-ticket-only|CVE-2024-24549"]


def test_partial_rollout_stale_inventory_failed_validation_rollback_withdrawal_and_scope_drift():
    report = reconcile_patch_plans_with_observations(RECONCILIATION_FIXTURE_PATH)
    by_id = {p["plan_id"]: p for p in report["plans"]}

    # Partial rollout + stale inventory
    partial = by_id["plan-partial-rollout-and-stale-inventory"]
    assert partial["reconciled_stage"] == "partial_rollout_with_stale_inventory"
    assert partial["observed_remediated_exposures"] == ["partial-app-1|CVE-2023-35116"]
    assert partial["residual_exposures"] == ["partial-app-2-stale|CVE-2023-35116"]

    # Failed validation reopens opportunity
    val_fail = by_id["plan-failed-validation"]
    assert val_fail["reconciled_stage"] == "validation_failed"
    assert val_fail["opportunity_reopened"] is True
    assert val_fail["observed_remediated_exposures"] == []

    # Rollback reopens opportunity with explanation
    rollback = by_id["plan-rollback-reopened"]
    assert rollback["reconciled_stage"] == "reopened_rollback"
    assert rollback["opportunity_reopened"] is True
    assert "rollback" in rollback["reopened_reason"].lower()

    # Withdrawn artifact reopens opportunity with explanation
    withdrawn = by_id["plan-withdrawn-artifact-reopened"]
    assert withdrawn["reconciled_stage"] == "reopened_withdrawn_artifact"
    assert withdrawn["opportunity_reopened"] is True
    assert "withdrawn" in withdrawn["reopened_reason"].lower()

    # Inventory/scope drift is separated from observed remediation
    drift = by_id["plan-scope-drift-only"]
    assert drift["reconciled_stage"] == "inventory_scope_drift_only"
    assert drift["observed_remediated_exposures"] == []
    assert drift["inventory_or_scope_drift_exposures"] == ["decommissioned-drift-app|CVE-2024-47554"]
    assert report["summary"]["inventory_or_scope_drift_exposure_count"] == 1


def test_privacy_preserving_request_export_broad_major_precision_and_co_release_mapping():
    raw = json.loads(REQUEST_INTAKE_FIXTURE_PATH.read_text(encoding="utf-8"))
    bundle = build_privacy_preserving_request_export(
        raw["raw_requests"],
        existing_catalog_patches=raw["existing_catalog_patches"],
        existing_osera_work=raw["existing_osera_work"],
        co_released_group_mapping=raw["co_released_group_mapping"],
    )

    assert bundle["schema_version"] == "osera-coverage-request/v1"
    assert bundle["submission_status"] == "local_export_not_submitted"
    # 2 compatible exact requests on spring-web@5.3.20 merged into 1, plus 1 broad-major request on tomcat 9.x
    assert len(bundle["requests"]) == 2

    serialized = json.dumps(bundle)
    for secret in ("PRIVATE-BANK-APP-01", "PRIVATE-TEAM-OWNER", "PRIVATE-ROOT", "PRIVATE-CONTRACT-999"):
        assert secret not in serialized

    spring_req = next(r for r in bundle["requests"] if "spring-web" in r["package"])
    assert spring_req["co_release_group"] == "org.springframework:spring-framework-bom"
    assert spring_req["already_covered_advisories"] == ["CVE-2024-22243"]
    assert spring_req["unresolved_advisories"] == ["CVE-2024-22259", "CVE-2024-22262"]
    assert spring_req["line_coverage_status"] == "supported_line_with_unresolved_new_work"
    assert spring_req["lifecycle_state"] == "in_progress"
    assert spring_req["counts_as_member_deployment"] is False

    # Broad-major request is NOT silently expanded into confirmed exact-line inventory
    tomcat_req = next(r for r in bundle["requests"] if "tomcat-embed-core" in r["package"])
    assert tomcat_req["scope"]["precision"] == "major"
    assert tomcat_req["scope"]["value"] == "9.x"
    assert tomcat_req["scope"]["confirmed_exact_inventory"] is False
    assert tomcat_req["line_coverage_status"] == "broad_major_line_review_required"


def test_unsupported_ecosystem_rejection_and_authenticated_intake_deduplication_with_rare_request_privacy():
    # Rejects unknown or unsupported ecosystem instead of coercing to Maven
    try:
        validate_and_normalize_coverage_request(
            {"package": "openssl", "line": "3.0.1", "precision": "exact", "advisories": ["CVE-2024-0727"]}
        )
        raise AssertionError("Expected ValueError for missing ecosystem")
    except ValueError as exc:
        assert "refusing to silently coerce to Maven" in str(exc)

    try:
        validate_and_normalize_coverage_request(
            {"identity": "pkg:conan/openssl@3.0.1", "line": "3.0.1", "precision": "exact", "advisories": ["CVE-2024-0727"]}
        )
        raise AssertionError("Expected ValueError for unsupported conan ecosystem")
    except ValueError as exc:
        assert "Unsupported ecosystem" in str(exc)

    raw = json.loads(REQUEST_INTAKE_FIXTURE_PATH.read_text(encoding="utf-8"))
    intake = deduplicate_authenticated_intake_submissions(raw["intake_submissions"], min_k_anonymity_members=2)
    by_pkg = {ln["package"]: ln for ln in intake["public_lines"]}

    # member-bank-alpha submitted twice for spring-web 5.3.20, plus member-bank-beta once -> unique demand is 2 (not 3!)
    spring_line = by_pkg["pkg:maven/org.springframework/spring-web"]
    assert spring_line["unique_member_demand_count"] == 2
    assert spring_line["duplicate_submissions_collapsed"] == 1
    assert spring_line["rare_request_privacy_redacted"] is False

    # commons-io 2.8.0 was requested by only 1 member (< k=2) -> rare-request rationale is redacted!
    commons_line = by_pkg["pkg:maven/commons-io/commons-io"]
    assert commons_line["unique_member_demand_count"] == 1
    assert commons_line["rare_request_privacy_redacted"] is True
    assert "Redacted" in commons_line["public_rationale_summary"]
    assert "mainframe" not in json.dumps(intake)
    assert "member-bank-alpha" not in json.dumps(intake)


def test_multi_occurrence_reconciliation_order_independence_staging_isolation_and_scoped_plans():
    """Verify multi-region/environment/timestamp deployment occurrences are preserved deterministically (#28)."""
    eu_patched = {
        "application_id": "payments-gateway",
        "deployment_id": "prod-eu",
        "environment": "production",
        "observed_purl": "pkg:maven/org.springframework/spring-web@5.3.20-osera-00002",
        "observed_at": "2026-10-28T10:00:00Z",
        "validation_status": "passed",
    }
    us_unpatched = {
        "application_id": "payments-gateway",
        "deployment_id": "prod-us",
        "environment": "production",
        "observed_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "observed_at": "2026-10-28T10:05:00Z",
        "validation_status": "pending",
    }
    staging_unpatched = {
        "application_id": "payments-gateway",
        "deployment_id": "staging-1",
        "environment": "staging",
        "observed_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "observed_at": "2026-10-29T00:00:00Z",
        "validation_status": "failed",
    }
    eu_older_unpatched = {
        "application_id": "payments-gateway",
        "deployment_id": "prod-eu",
        "environment": "production",
        "observed_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "observed_at": "2026-10-25T08:00:00Z",
        "validation_status": "pending",
    }

    whole_prod_plan = {
        "plan_id": "plan-whole-prod",
        "opportunity_id": "opp-spring-web",
        "current_stage": "deployed",
        "source_artifact_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "selected_artifact_purl": "pkg:maven/org.springframework/spring-web@5.3.20-osera-00002",
        "required_environment": "production",
        "target_applications": ["payments-gateway"],
        "expected_fixed_advisories": ["CVE-2024-22243"],
    }
    eu_scoped_plan = {
        "plan_id": "plan-eu-only",
        "opportunity_id": "opp-spring-web-eu",
        "current_stage": "deployed",
        "source_artifact_purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "selected_artifact_purl": "pkg:maven/org.springframework/spring-web@5.3.20-osera-00002",
        "required_environment": "production",
        "target_applications": ["payments-gateway"],
        "target_deployments": ["prod-eu"],
        "expected_fixed_advisories": ["CVE-2024-22243"],
    }

    obs_list = [eu_patched, us_unpatched, staging_unpatched, eu_older_unpatched]
    rep_forward = reconcile_patch_plans_with_observations(
        {"deployment_observations": obs_list, "plans": [whole_prod_plan, eu_scoped_plan]}
    )
    rep_reverse = reconcile_patch_plans_with_observations(
        {"deployment_observations": list(reversed(obs_list)), "plans": [whole_prod_plan, eu_scoped_plan]}
    )
    assert rep_forward == rep_reverse

    by_id = {p["plan_id"]: p for p in rep_forward["plans"]}
    # Whole-production plan reports partial_rollout (never verified!) because prod-us is still unpatched
    whole = by_id["plan-whole-prod"]
    assert whole["reconciled_stage"] == "partial_rollout"
    assert whole["observed_remediated_exposures"] == []
    assert whole["residual_exposures"] == ["payments-gateway|CVE-2024-22243"]
    assert whole["occurrence_breakdown"]["verified_occurrences"] == ["payments-gateway@prod-eu"]
    assert whole["occurrence_breakdown"]["unpatched_occurrences"] == ["payments-gateway@prod-us"]

    # EU-scoped plan verifies for prod-eu while recording prod-us as out_of_scope_unpatched_occurrences
    eu_only = by_id["plan-eu-only"]
    assert eu_only["reconciled_stage"] == "verified"
    assert eu_only["observed_remediated_exposures"] == ["payments-gateway@prod-eu|CVE-2024-22243"]
    assert eu_only["residual_exposures"] == []
    assert eu_only["occurrence_breakdown"]["out_of_scope_unpatched_occurrences"] == ["payments-gateway@prod-us"]


class PatchVerificationAndRequestsTestCase(unittest.TestCase):
    def test_all(self):
        test_closed_ticket_recipe_or_osera_issue_without_deployment_cannot_verify_remediation()
        test_partial_rollout_stale_inventory_failed_validation_rollback_withdrawal_and_scope_drift()
        test_privacy_preserving_request_export_broad_major_precision_and_co_release_mapping()
        test_unsupported_ecosystem_rejection_and_authenticated_intake_deduplication_with_rare_request_privacy()
        test_multi_occurrence_reconciliation_order_independence_staging_isolation_and_scoped_plans()


if __name__ == "__main__":
    unittest.main()

import copy
import json
from pathlib import Path

from patch_readiness import evaluate_patch_readiness, evaluate_patch_readiness_bundle


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "data" / "fixtures" / "patch-readiness-sample.json"


def _load_candidates() -> dict[str, dict]:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return {item["id"]: item for item in payload["candidates"]}


def test_source_pass_alone_cannot_imply_promotion_or_member_approval():
    candidates = _load_candidates()
    result = evaluate_patch_readiness(candidates["source-pass-only"])
    assert result["stages"]["source_fitness"]["status"] == "pass"
    assert result["stages"]["source_fitness"]["traceability"]["artifact_digest"] is None
    assert result["stages"]["artifact_promotion"]["status"] == "pending"
    assert result["stages"]["member_validation"]["status"] == "pending"
    assert result["overall_status"] == "source_only"
    assert result["eligible_for_deployment"] is False
    # CP-REL-004 proposal warnings stay separate from adopted blocking requirements
    assert result["blockers"] == []
    assert any(w["code"] == "CP-REL-004" and w["tier"] == "proposal" for w in result["proposal_warnings"])


def test_evidence_disagreement_broken_required_chain_and_unverified_links_block_readiness():
    candidates = _load_candidates()
    result = evaluate_patch_readiness(candidates["evidence-disagreement-and-broken-required-chain"])
    assert result["overall_status"] == "blocked"
    assert result["eligible_for_deployment"] is False
    blocker_codes = {b["code"] for b in result["blockers"]}
    assert "EVIDENCE_DOCUMENT_DISAGREEMENT" in blocker_codes
    assert "BROKEN_REQUIRED_CHAIN:maven:org.springframework:spring-core:5.3.39-osera.1" in blocker_codes
    assert "UNVERIFIED_ATTESTATION_SIGNATURE" in blocker_codes


def test_unrelated_broken_artifacts_and_proposals_do_not_block_independent_plan():
    candidates = _load_candidates()
    result = evaluate_patch_readiness(candidates["ready-with-unrelated-broken-artifact"])
    assert result["overall_status"] == "ready"
    assert result["eligible_for_deployment"] is True
    assert result["blockers"] == []
    # Unrelated broken artifact outside closure is surfaced as a non-blocking notice
    assert len(result["unrelated_artifact_notices"]) == 1
    assert "spring-webflux" in result["unrelated_artifact_notices"][0]["artifact_id"]
    # CP-REL-004 remains visible as a proposal warning without blocking
    assert len(result["proposal_warnings"]) == 1
    assert result["proposal_warnings"][0]["code"] == "CP-REL-004"
    # Immutable traceability across all 3 stages
    assert result["stages"]["source_fitness"]["traceability"]["library_commit"] == "0123456789abcdef0123456789abcdef01234567"
    assert result["stages"]["artifact_promotion"]["traceability"]["artifact_digest"].startswith("sha256:aaaa1111")
    assert result["stages"]["member_validation"]["traceability"]["policy_id"] == "member-tier1-prod-policy"
    assert result["stages"]["member_validation"]["traceability"]["policy_version"] == "2026.11"


def test_unsigned_rehearsal_and_missing_mandatory_checks_cannot_yield_ready():
    candidates = _load_candidates()
    cand = json.loads(json.dumps(candidates["ready-with-unrelated-broken-artifact"]))
    cand["artifact_promotion"]["rehearsal"] = True
    cand["source_fitness"]["checks"] = [
        c for c in cand["source_fitness"]["checks"] if c["id"] != "REL-006"
    ]
    result = evaluate_patch_readiness(cand)
    assert result["overall_status"] == "blocked"
    assert result["eligible_for_deployment"] is False
    codes = {b["code"] for b in result["blockers"]}
    assert "UNSIGNED_REHEARSAL_RESULT" in codes
    assert "MISSING_MANDATORY_CHECK:REL-006" in codes


def test_missing_required_companion_chain_blocks_readiness():
    candidates = _load_candidates()
    cand = copy.deepcopy(candidates["ready-with-unrelated-broken-artifact"])
    cand["artifact_promotion"]["artifact_chains"] = [
        x
        for x in cand["artifact_promotion"]["artifact_chains"]
        if "spring-core" not in x["artifact_id"]
    ]
    result = evaluate_patch_readiness(cand)
    assert result["overall_status"] == "blocked"
    assert result["eligible_for_deployment"] is False
    codes = {b["code"] for b in result["blockers"]}
    assert "MISSING_REQUIRED_CHAIN:maven:org.springframework:spring-core:5.3.39-osera.1" in codes


def test_mismatched_or_missing_member_evidence_binding_blocks_readiness():
    candidates = _load_candidates()
    wrong_binding = copy.deepcopy(candidates["ready-with-unrelated-broken-artifact"])
    wrong_binding["member_validation"]["bound_evidence_digest"] = "sha256:WRONG"
    res_wrong = evaluate_patch_readiness(wrong_binding)
    assert res_wrong["overall_status"] == "blocked"
    assert res_wrong["eligible_for_deployment"] is False
    assert any(b["code"] == "MEMBER_EVIDENCE_BINDING_MISMATCH" for b in res_wrong["blockers"])

    missing_binding = copy.deepcopy(candidates["ready-with-unrelated-broken-artifact"])
    missing_binding["member_validation"].pop("bound_evidence_digest", None)
    res_missing = evaluate_patch_readiness(missing_binding)
    assert res_missing["overall_status"] == "blocked"
    assert res_missing["eligible_for_deployment"] is False
    assert any(b["code"] == "MISSING_MEMBER_EVIDENCE_BINDING" for b in res_missing["blockers"])


def test_mandatory_policy_check_failure_cannot_be_made_nonblocking_by_input():
    candidates = _load_candidates()
    cand = copy.deepcopy(candidates["ready-with-unrelated-broken-artifact"])
    next(x for x in cand["source_fitness"]["checks"] if x["id"] == "FORK-001").update(
        status="fail",
        blocking=False,
    )
    result = evaluate_patch_readiness(cand)
    assert result["overall_status"] == "blocked"
    assert result["eligible_for_deployment"] is False
    assert any(b["code"] == "CHECK_FAILED:FORK-001" for b in result["blockers"])


def test_evaluate_patch_readiness_bundle_returns_all_scenarios():
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    bundle = evaluate_patch_readiness_bundle(payload)
    assert set(bundle["by_id"].keys()) == {
        "source-pass-only",
        "evidence-disagreement-and-broken-required-chain",
        "ready-with-unrelated-broken-artifact",
    }
    assert bundle["by_id"]["ready-with-unrelated-broken-artifact"]["overall_status"] == "ready"
    assert bundle["by_id"]["source-pass-only"]["overall_status"] == "source_only"
    assert bundle["by_id"]["evidence-disagreement-and-broken-required-chain"]["overall_status"] == "blocked"


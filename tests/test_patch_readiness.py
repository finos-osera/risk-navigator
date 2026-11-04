import copy
import json
import subprocess
import sys
from pathlib import Path

from patch_readiness import (
    DEFAULT_DATASET_LIBRARY_ID,
    attach_patch_readiness_to_dataset,
    evaluate_patch_readiness,
    evaluate_patch_readiness_bundle,
    main as patch_readiness_main,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT_DIR / "data" / "fixtures" / "patch-readiness-sample.json"
SAMPLE_DATASET_PATH = ROOT_DIR / "data" / "finos-sample-platform.json"


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


def test_default_write_dataset_attaches_spring_web_readiness_and_preserves_adoption_data(tmp_path):
    assert DEFAULT_DATASET_LIBRARY_ID == "maven|org.springframework|spring-web|5.3.39"
    committed_dataset = json.loads(SAMPLE_DATASET_PATH.read_text(encoding="utf-8"))
    committed_spring_web = next(
        (lib for lib in committed_dataset.get("libraries", []) if lib.get("id") == DEFAULT_DATASET_LIBRARY_ID),
        None,
    )
    assert committed_spring_web is not None
    assert committed_spring_web.get("patch_readiness", {}).get("overall_status") == "ready"
    assert set(committed_spring_web.get("patch_readiness_scenarios", {}).keys()) == {
        "source-pass-only",
        "evidence-disagreement-and-broken-required-chain",
        "ready-with-unrelated-broken-artifact",
    }
    assert committed_dataset.get("patch_feed_adoption") is not None

    # Strip readiness fields on a temp copy and verify the documented default CLI invocation re-attaches them
    stripped_dataset = copy.deepcopy(committed_dataset)
    original_top_adoption = copy.deepcopy(stripped_dataset.get("patch_feed_adoption"))
    for lib in stripped_dataset.get("libraries", []):
        if lib.get("id") == DEFAULT_DATASET_LIBRARY_ID:
            lib.pop("patch_readiness", None)
            lib.pop("patch_readiness_scenarios", None)
    temp_dataset_path = tmp_path / "finos-sample-platform.json"
    temp_dataset_path.write_text(json.dumps(stripped_dataset, indent=2) + "\n", encoding="utf-8")

    rc = patch_readiness_main([
        "--fixture",
        str(FIXTURE_PATH),
        "--write-dataset",
        str(temp_dataset_path),
    ])
    assert rc == 0

    written = json.loads(temp_dataset_path.read_text(encoding="utf-8"))
    assert written.get("patch_feed_adoption") == original_top_adoption
    spring_web = next(
        (lib for lib in written.get("libraries", []) if lib.get("id") == DEFAULT_DATASET_LIBRARY_ID),
        None,
    )
    assert spring_web is not None
    assert spring_web["patch_readiness"]["overall_status"] == "ready"
    assert spring_web["patch_readiness"]["verifier_mode"] == "simulated_gate_fixture_evidence"
    assert set(spring_web["patch_readiness_scenarios"].keys()) == {
        "source-pass-only",
        "evidence-disagreement-and-broken-required-chain",
        "ready-with-unrelated-broken-artifact",
    }


def test_write_dataset_fails_clearly_when_library_id_matches_no_library(tmp_path):
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    bundle = evaluate_patch_readiness_bundle(payload)
    dataset = {"libraries": [{"id": DEFAULT_DATASET_LIBRARY_ID, "name": "spring-web"}]}

    try:
        attach_patch_readiness_to_dataset(
            dataset,
            bundle,
            library_id="maven:org.springframework:spring-web:5.3.39",
        )
        raise AssertionError("Expected ValueError for unmatched library_id")
    except ValueError as exc:
        assert "maven:org.springframework:spring-web:5.3.39" in str(exc)

    temp_dataset_path = tmp_path / "unmatched-dataset.json"
    original_text = json.dumps(dataset, indent=2) + "\n"
    temp_dataset_path.write_text(original_text, encoding="utf-8")

    try:
        patch_readiness_main([
            "--fixture",
            str(FIXTURE_PATH),
            "--write-dataset",
            str(temp_dataset_path),
            "--library-id",
            "maven:org.springframework:spring-web:5.3.39",
        ])
        raise AssertionError("Expected SystemExit for unmatched --library-id")
    except SystemExit as exc_info:
        assert "maven:org.springframework:spring-web:5.3.39" in str(exc_info)
        assert "was not found in dataset libraries" in str(exc_info)
    assert temp_dataset_path.read_text(encoding="utf-8") == original_text


def test_write_dataset_rejects_ambiguous_or_unknown_selection(tmp_path):
    for case in ("duplicate_library", "unknown_candidate"):
        dataset = json.loads(SAMPLE_DATASET_PATH.read_text(encoding="utf-8"))
        extra_args = []
        if case == "duplicate_library":
            target = next(lib for lib in dataset["libraries"] if lib["id"] == DEFAULT_DATASET_LIBRARY_ID)
            dataset["libraries"].append(copy.deepcopy(target))
            expected_error = "ambiguous"
            rejected_id = DEFAULT_DATASET_LIBRARY_ID
        else:
            rejected_id = "does-not-exist"
            extra_args = ["--candidate-id", rejected_id]
            expected_error = "candidate"

        path = tmp_path / f"dataset-{case}.json"
        path.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
        before = path.read_bytes()

        result = subprocess.run(
            [
                sys.executable,
                str(ROOT_DIR / "scripts" / "patch_readiness.py"),
                "--fixture",
                str(FIXTURE_PATH),
                "--write-dataset",
                str(path),
                *extra_args,
            ],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0, f"Invalid selection ({case}) must fail, not silently write a dataset"
        assert expected_error in result.stderr.lower()
        assert rejected_id in result.stderr
        assert path.read_bytes() == before, f"Rejected selection ({case}) must leave the file unchanged"





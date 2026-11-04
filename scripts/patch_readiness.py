#!/usr/bin/env python3
"""Evaluate and explain patch readiness across source fitness, artifact promotion, and member policy.

Implements the three-stage readiness model for Issue #25:
1. Source fitness (OSERA source checks; artifact_digest may be null)
2. Artifact promotion & reconciliation evidence (immutable digests, companion closure, verified signatures)
3. Member validation (institution-specific policy & acceptance gate)
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Set


VALID_CHECK_STATUSES = {"pass", "fail", "warn", "not-tested", "not-applicable"}
DEFAULT_ADOPTED_MANDATORY_CHECKS = (
    "FORK-001",
    "SRC-001",
    "REL-001",
    "REL-006",
    "EVD-001",
)
DEFAULT_DATASET_LIBRARY_ID = "maven|org.springframework|spring-web|5.3.39"
DEFAULT_CANDIDATE_ID = "ready-with-unrelated-broken-artifact"


class AttestationVerifier(Protocol):
    """Interface for trusted attestation verification and final promotion gate connectors."""

    def verify_attestation(self, promotion_evidence: Dict[str, Any]) -> bool:
        """Return True only when cryptographic signature and provenance are verified by a trusted gate."""


@dataclass
class DefaultGateVerifier:
    """Default conservative verifier: a signature/verdict link alone is never treated as verified."""

    trusted_verifiers: Set[str] = field(default_factory=lambda: {"osera-trusted-gate", "member-attestation-gate"})

    def verify_attestation(self, promotion_evidence: Dict[str, Any]) -> bool:
        if not isinstance(promotion_evidence, dict):
            return False
        if promotion_evidence.get("rehearsal") is True:
            return False
        attestation = promotion_evidence.get("attestation")
        if not isinstance(attestation, dict):
            return False
        # Presence of signature_url or verdict_url alone is insufficient
        if attestation.get("cryptographically_verified") is not True:
            return False
        verifier_id = str(attestation.get("verified_by") or "").strip()
        if not verifier_id or verifier_id not in self.trusted_verifiers:
            return False
        bound_digest = str(attestation.get("subject_digest") or "").strip()
        artifact_digest = str(promotion_evidence.get("artifact_digest") or "").strip()
        return bool(bound_digest and artifact_digest and bound_digest == artifact_digest)


def evaluate_patch_readiness(
    candidate: Dict[str, Any],
    verifier: Optional[AttestationVerifier] = None,
    mandatory_checks: Sequence[str] = DEFAULT_ADOPTED_MANDATORY_CHECKS,
) -> Dict[str, Any]:
    """Evaluate a patch candidate across source fitness, artifact promotion, and member policy."""
    gate_verifier = verifier or DefaultGateVerifier()

    closure_ids: Set[str] = set(str(x).strip() for x in (candidate.get("proposed_closure_artifacts") or []) if str(x).strip())
    primary_artifact_id = str(candidate.get("artifact_id") or "").strip()
    if primary_artifact_id:
        closure_ids.add(primary_artifact_id)

    source_raw = candidate.get("source_fitness") or {}
    promotion_raw = candidate.get("artifact_promotion") or {}
    member_raw = candidate.get("member_validation") or {}

    blockers: List[Dict[str, str]] = []
    adopted_warnings: List[Dict[str, str]] = []
    proposal_warnings: List[Dict[str, str]] = []
    unrelated_notices: List[Dict[str, str]] = []

    # --- Stage 1: Source Fitness ---
    source_trace = {
        "pack_version": source_raw.get("pack_version"),
        "library_commit": source_raw.get("library_commit"),
        "release_commit": source_raw.get("release_commit"),
        "evidence_file_digest": source_raw.get("evidence_file_digest"),
        "artifact_digest": source_raw.get("artifact_digest"),  # Explicitly allowed to be None at source stage
        "evaluated_at": source_raw.get("evaluated_at"),
    }

    checks_raw = source_raw.get("checks") or []
    normalized_checks: List[Dict[str, Any]] = []
    seen_adopted_checks: Dict[str, str] = {}
    mandatory_set: Set[str] = {str(m).strip() for m in mandatory_checks if str(m).strip()}

    for chk in checks_raw:
        if not isinstance(chk, dict):
            continue
        check_id = str(chk.get("id") or "").strip()
        status = str(chk.get("status") or "not-tested").strip().lower()
        if status not in VALID_CHECK_STATUSES:
            status = "not-tested"
        is_mandatory_policy_check = check_id in mandatory_set
        tier = str(chk.get("tier") or ("proposal" if check_id.startswith("CP-") else "adopted")).strip().lower()
        is_proposal = False if is_mandatory_policy_check else (tier == "proposal" or check_id.startswith("CP-"))
        effective_blocking = True if is_mandatory_policy_check else bool(chk.get("blocking", not is_proposal))
        entry = {
            "id": check_id,
            "version": chk.get("version") or source_raw.get("pack_version") or "0.1.0",
            "status": status,
            "tier": "proposal" if is_proposal else "adopted",
            "blocking": effective_blocking,
            "expected": chk.get("expected"),
            "observed": chk.get("observed"),
            "freshness": chk.get("freshness") or source_raw.get("evaluated_at"),
            "reason": str(chk.get("reason") or "").strip(),
        }
        normalized_checks.append(entry)

        if is_proposal:
            if status in {"warn", "fail", "not-tested"}:
                proposal_warnings.append({
                    "code": check_id,
                    "tier": "proposal",
                    "status": status,
                    "message": entry["reason"] or f"Proposal check {check_id} reported {status} (non-blocking proposal).",
                })
            continue

        seen_adopted_checks[check_id] = status
        if status == "fail" and effective_blocking:
            blockers.append({
                "stage": "source_fitness",
                "code": f"CHECK_FAILED:{check_id}",
                "message": entry["reason"] or f"Adopted check {check_id} failed.",
            })
        elif status == "not-tested" and effective_blocking:
            blockers.append({
                "stage": "source_fitness",
                "code": f"CHECK_NOT_TESTED:{check_id}",
                "message": entry["reason"] or f"Mandatory adopted check {check_id} was not tested.",
            })
        elif is_mandatory_policy_check and status != "pass":
            blockers.append({
                "stage": "source_fitness",
                "code": f"MANDATORY_CHECK_NON_PASS:{check_id}",
                "message": entry["reason"] or f"Mandatory adopted check {check_id} must pass (observed {status}).",
            })
        elif status == "warn":
            adopted_warnings.append({
                "code": check_id,
                "tier": "adopted",
                "status": "warn",
                "message": entry["reason"] or f"Adopted check {check_id} reported warning.",
            })

    for req_id in mandatory_checks:
        if req_id not in seen_adopted_checks:
            blockers.append({
                "stage": "source_fitness",
                "code": f"MISSING_MANDATORY_CHECK:{req_id}",
                "message": f"Mandatory adopted OSERA check {req_id} is missing from source fitness results.",
            })

    if not source_trace["library_commit"] or not source_trace["evidence_file_digest"]:
        blockers.append({
            "stage": "source_fitness",
            "code": "MISSING_SOURCE_TRACEABILITY",
            "message": "Source fitness result is missing immutable library_commit or evidence_file_digest.",
        })

    source_stage_blockers = [b for b in blockers if b["stage"] == "source_fitness"]
    source_status = "pass" if not source_stage_blockers else "fail"

    # --- Stage 2: Artifact Promotion & Reconciliation ---
    promotion_trace = {
        "pack_version": promotion_raw.get("pack_version"),
        "release_commit": promotion_raw.get("release_commit"),
        "artifact_digest": promotion_raw.get("artifact_digest"),
        "observed_artifact_digest": promotion_raw.get("observed_artifact_digest"),
        "evidence_file_digest": promotion_raw.get("evidence_file_digest"),
        "observed_evidence_file_digest": promotion_raw.get("observed_evidence_file_digest"),
        "evaluated_at": promotion_raw.get("evaluated_at"),
        "rehearsal": bool(promotion_raw.get("rehearsal", False)),
        "global_status": promotion_raw.get("global_status"),
        "signature_url": (promotion_raw.get("attestation") or {}).get("signature_url"),
        "verdict_url": (promotion_raw.get("attestation") or {}).get("verdict_url"),
    }

    has_promotion_payload = bool(promotion_raw and isinstance(promotion_raw, dict))
    signature_verified = gate_verifier.verify_attestation(promotion_raw) if has_promotion_payload else False

    if not has_promotion_payload:
        promotion_status = "pending"
    else:
        if promotion_raw.get("rehearsal") is True:
            blockers.append({
                "stage": "artifact_promotion",
                "code": "UNSIGNED_REHEARSAL_RESULT",
                "message": "Rehearsal build results cannot establish release promotion readiness.",
            })
        if not promotion_trace["artifact_digest"]:
            blockers.append({
                "stage": "artifact_promotion",
                "code": "MISSING_ARTIFACT_DIGEST",
                "message": "Artifact promotion requires a non-null immutable artifact_digest.",
            })
        if (
            promotion_trace["artifact_digest"]
            and promotion_trace["observed_artifact_digest"]
            and promotion_trace["artifact_digest"] != promotion_trace["observed_artifact_digest"]
        ):
            blockers.append({
                "stage": "artifact_promotion",
                "code": "ARTIFACT_DIGEST_MISMATCH",
                "message": "Declared artifact_digest disagrees with observed binary digest.",
            })
        if (
            promotion_trace["evidence_file_digest"]
            and promotion_trace["observed_evidence_file_digest"]
            and promotion_trace["evidence_file_digest"] != promotion_trace["observed_evidence_file_digest"]
        ):
            blockers.append({
                "stage": "artifact_promotion",
                "code": "EVIDENCE_DOCUMENT_DISAGREEMENT",
                "message": "Promotion summary document disagrees with underlying evidence file digest.",
            })
        if (
            source_trace["release_commit"]
            and promotion_trace["release_commit"]
            and source_trace["release_commit"] != promotion_trace["release_commit"]
        ):
            blockers.append({
                "stage": "artifact_promotion",
                "code": "RELEASE_COMMIT_MISMATCH",
                "message": "Promotion artifact release_commit does not match source fitness release_commit.",
            })

        # Evaluate artifact chains scoped to the proposed artifact/companion closure
        present_chain_ids: Set[str] = set()
        for chain in (promotion_raw.get("artifact_chains") or []):
            if not isinstance(chain, dict):
                continue
            art_id = str(chain.get("artifact_id") or "").strip()
            if art_id:
                present_chain_ids.add(art_id)
            chain_status = str(chain.get("status") or "unknown").strip().lower()
            in_closure = (not closure_ids) or (art_id in closure_ids) or bool(chain.get("required_for_plan"))
            if chain_status != "verified":
                if in_closure:
                    blockers.append({
                        "stage": "artifact_promotion",
                        "code": f"BROKEN_REQUIRED_CHAIN:{art_id or 'unknown'}",
                        "message": str(chain.get("reason") or f"Required companion artifact chain {art_id} is {chain_status}."),
                    })
                else:
                    unrelated_notices.append({
                        "artifact_id": art_id,
                        "status": chain_status,
                        "message": str(chain.get("reason") or f"Unrelated artifact {art_id} is {chain_status} (outside proposed closure)."),
                    })

        # Every required closure artifact must have explicit chain coverage in artifact_chains
        for req_art_id in sorted(closure_ids):
            if req_art_id not in present_chain_ids:
                blockers.append({
                    "stage": "artifact_promotion",
                    "code": f"MISSING_REQUIRED_CHAIN:{req_art_id}",
                    "message": f"Required closure artifact {req_art_id} is missing from artifact_promotion.artifact_chains.",
                })

        if not signature_verified:
            blockers.append({
                "stage": "artifact_promotion",
                "code": "UNVERIFIED_ATTESTATION_SIGNATURE",
                "message": "Present signature/verdict links or global status are not verified by a trusted attestation gate.",
            })

        promo_blockers = [b for b in blockers if b["stage"] == "artifact_promotion"]
        promotion_status = "verified" if not promo_blockers else "blocked"

    # --- Stage 3: Member Validation ---
    member_trace = {
        "policy_id": member_raw.get("policy_id"),
        "policy_version": member_raw.get("policy_version"),
        "decision": member_raw.get("decision"),
        "evaluated_at": member_raw.get("evaluated_at"),
        "bound_artifact_digest": member_raw.get("bound_artifact_digest"),
        "bound_evidence_digest": member_raw.get("bound_evidence_digest"),
    }

    if not member_raw or not member_trace["decision"]:
        member_status = "pending"
    else:
        decision = str(member_trace["decision"]).strip().lower()
        if not member_trace["policy_id"] or not member_trace["policy_version"]:
            blockers.append({
                "stage": "member_validation",
                "code": "MISSING_MEMBER_POLICY_VERSION",
                "message": "Member validation must record immutable policy_id and policy_version.",
            })
        if (
            promotion_trace["artifact_digest"]
            and member_trace["bound_artifact_digest"] != promotion_trace["artifact_digest"]
        ):
            blockers.append({
                "stage": "member_validation",
                "code": "MEMBER_DIGEST_BINDING_MISMATCH",
                "message": "Member validation decision is not bound to the promoted artifact_digest.",
            })
        expected_evidence_digest = (
            promotion_trace.get("evidence_file_digest")
            or source_trace.get("evidence_file_digest")
        )
        bound_evidence_digest = str(member_trace.get("bound_evidence_digest") or "").strip()
        if not bound_evidence_digest:
            blockers.append({
                "stage": "member_validation",
                "code": "MISSING_MEMBER_EVIDENCE_BINDING",
                "message": "Member validation decision must record a non-empty bound_evidence_digest.",
            })
        elif (
            (expected_evidence_digest and bound_evidence_digest != expected_evidence_digest)
            or (
                source_trace.get("evidence_file_digest")
                and bound_evidence_digest != source_trace["evidence_file_digest"]
            )
        ):
            blockers.append({
                "stage": "member_validation",
                "code": "MEMBER_EVIDENCE_BINDING_MISMATCH",
                "message": "Member validation bound_evidence_digest does not match the evaluated evidence_file_digest.",
            })
        if decision != "approved":
            blockers.append({
                "stage": "member_validation",
                "code": f"MEMBER_POLICY_{decision.upper()}",
                "message": str(member_raw.get("reason") or f"Member policy decision is '{decision}'."),
            })
        member_stage_blockers = [b for b in blockers if b["stage"] == "member_validation"]
        member_status = "approved" if (decision == "approved" and not member_stage_blockers) else "rejected"

    # --- Overall Readiness Verdict ---
    if blockers:
        overall_status = "blocked"
    elif source_status == "pass" and promotion_status == "pending":
        overall_status = "source_only"
    elif source_status == "pass" and promotion_status == "verified" and member_status == "pending":
        overall_status = "member_validation_pending"
    elif source_status == "pass" and promotion_status == "verified" and member_status == "approved":
        overall_status = "ready"
    else:
        overall_status = "incomplete"

    return {
        "candidate_id": candidate.get("id"),
        "artifact_id": primary_artifact_id or None,
        "overall_status": overall_status,
        "eligible_for_deployment": overall_status == "ready",
        "verifier_mode": "simulated_gate_fixture_evidence",
        "stages": {
            "source_fitness": {
                "status": source_status,
                "traceability": source_trace,
                "checks": normalized_checks,
            },
            "artifact_promotion": {
                "status": promotion_status,
                "signature_verified": signature_verified,
                "traceability": promotion_trace,
            },
            "member_validation": {
                "status": member_status,
                "traceability": member_trace,
            },
        },
        "blockers": blockers,
        "adopted_warnings": adopted_warnings,
        "proposal_warnings": proposal_warnings,
        "unrelated_artifact_notices": unrelated_notices,
    }


def evaluate_patch_readiness_bundle(
    bundle: Dict[str, Any],
    verifier: Optional[AttestationVerifier] = None,
    mandatory_checks: Sequence[str] = DEFAULT_ADOPTED_MANDATORY_CHECKS,
) -> Dict[str, Any]:
    """Evaluate all patch candidates in a fixture bundle."""
    candidates = bundle.get("candidates") if isinstance(bundle, dict) else []
    evaluated: List[Dict[str, Any]] = []
    by_id: Dict[str, Dict[str, Any]] = {}
    for cand in candidates or []:
        if not isinstance(cand, dict):
            continue
        res = evaluate_patch_readiness(cand, verifier=verifier, mandatory_checks=mandatory_checks)
        evaluated.append(res)
        cid = str(cand.get("id") or "").strip()
        if cid:
            by_id[cid] = res
    return {
        "schema_version": bundle.get("schema_version", "0.1") if isinstance(bundle, dict) else "0.1",
        "verifier_mode": "simulated_gate_fixture_evidence",
        "candidates": evaluated,
        "by_id": by_id,
    }


def attach_patch_readiness_to_dataset(
    dataset: Dict[str, Any],
    bundle_eval: Dict[str, Any],
    library_id: str = DEFAULT_DATASET_LIBRARY_ID,
    candidate_id: str = DEFAULT_CANDIDATE_ID,
) -> int:
    """Attach evaluated patch_readiness and scenario map to matching library records in dataset.

    Raises ValueError when no library in dataset matches library_id or candidate_id is missing.
    """
    by_id = bundle_eval.get("by_id") if isinstance(bundle_eval, dict) else {}
    candidates = bundle_eval.get("candidates") if isinstance(bundle_eval, dict) else []
    primary = (by_id or {}).get(candidate_id) or (candidates[0] if candidates else None)
    if primary is None:
        raise ValueError(f"Candidate ID {candidate_id!r} was not found in evaluated readiness bundle.")

    matched = 0
    for lib in (dataset.get("libraries") or []) if isinstance(dataset, dict) else []:
        if isinstance(lib, dict) and lib.get("id") == library_id:
            lib["patch_readiness"] = primary
            lib["patch_readiness_scenarios"] = by_id
            matched += 1

    if matched == 0:
        raise ValueError(
            f"Target library ID {library_id!r} was not found in dataset libraries."
        )
    return matched


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate OSERA patch readiness candidates (#25).")
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("data/fixtures/patch-readiness-sample.json"),
        help="Path to patch readiness candidate fixture JSON.",
    )
    parser.add_argument(
        "--candidate-id",
        type=str,
        default=DEFAULT_CANDIDATE_ID,
        help="Default candidate ID to attach as primary patch_readiness when writing to a dataset.",
    )
    parser.add_argument(
        "--write-dataset",
        type=Path,
        default=None,
        help="Optional dataset JSON path (e.g. data/finos-sample-platform.json) to attach patch_readiness on the matching library.",
    )
    parser.add_argument(
        "--library-id",
        type=str,
        default=DEFAULT_DATASET_LIBRARY_ID,
        help="Target library ID in --write-dataset to populate with patch_readiness and patch_readiness_scenarios.",
    )
    args = parser.parse_args(argv)
    bundle_raw = json.loads(args.fixture.read_text(encoding="utf-8"))
    bundle_eval = evaluate_patch_readiness_bundle(bundle_raw)
    if args.write_dataset:
        dataset = json.loads(args.write_dataset.read_text(encoding="utf-8"))
        try:
            attach_patch_readiness_to_dataset(
                dataset,
                bundle_eval,
                library_id=args.library_id,
                candidate_id=args.candidate_id,
            )
        except ValueError as exc:
            raise SystemExit(
                f"error: --write-dataset ({args.write_dataset}) failed: {exc}"
            ) from exc
        args.write_dataset.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(bundle_eval, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

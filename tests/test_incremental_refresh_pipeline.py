import copy
import json
import tempfile
import unittest
from pathlib import Path

from incremental_refresh_pipeline import (
    DEFAULT_COLLECTIONS_CONFIG_PATH,
    DEFAULT_PIPELINE_STATUS_PATH,
    build_assessment_receipt,
    compare_assessment_snapshots,
    compute_canonical_assessment_sha256,
    load_collections_config,
    publish_collection_artifacts_safely,
    resolve_inventory_scoped_osv_across_collections,
    run_incremental_inventory_scan,
    sanitize_public_failure_summary,
    update_pipeline_status_document,
    validate_assessment_receipt,
)


class FakeOsvClient:
    """Deterministic offline OSV mock supporting multi-page querybatch, detail fetches, and injected errors."""

    def __init__(self, batch_map: dict[str, list[dict]], details_map: dict[str, dict], fail_on_page_2: bool = False):
        self.batch_map = batch_map
        self.details_map = details_map
        self.fail_on_page_2 = fail_on_page_2
        self.batch_calls: list[list[dict]] = []
        self.detail_calls: list[str] = []

    def querybatch(self, queries: list[dict]) -> dict:
        self.batch_calls.append(copy.deepcopy(queries))
        results = []
        for q in queries:
            pkg = q["package"]["name"]
            ver = q["version"]
            key = f"{pkg}@{ver}"
            page_token = q.get("page_token")
            if page_token == "page-2":
                if self.fail_on_page_2:
                    raise RuntimeError("Simulated OSV page-2 network failure")
                results.append({"vulns": self.batch_map.get(f"{key}#page2", [])})
            else:
                v_list = self.batch_map.get(key, [])
                if f"{key}#page2" in self.batch_map:
                    results.append({"vulns": v_list, "next_page_token": "page-2"})
                else:
                    results.append({"vulns": v_list})
        return {"results": results}

    def get_vuln(self, vuln_id: str) -> dict:
        self.detail_calls.append(vuln_id)
        return copy.deepcopy(self.details_map[vuln_id])


def test_collections_config_and_incremental_inventory_reuse_readme_change_and_shrink_guard():
    cfg = load_collections_config(DEFAULT_COLLECTIONS_CONFIG_PATH)
    finos_cfg = next(c for c in cfg["collections"] if c["collection_id"] == "finos-github-org")

    initial_repos = [
        {
            "repo_id": "R1",
            "full_name": "finos/Alloy",
            "commit_sha": "aaa111",
            "dependency_files": [{"path": "pom.xml", "sha256": "hash-pom-1"}],
            "extracted_edges": [
                {"ecosystem": "maven", "package": "org.springframework:spring-web", "version": "5.3.20", "direct": True},
                {"ecosystem": "npm", "package": "lodash", "version": "^4.17.0", "direct": True},
                {"ecosystem": "conan", "package": "openssl", "version": "3.0.1", "direct": True},
            ],
        },
        {
            "repo_id": "R2",
            "full_name": "finos/legend-engine",
            "commit_sha": "bbb222",
            "dependency_files": [{"path": "pom.xml", "sha256": "hash-pom-2"}],
            "extracted_edges": [
                {"ecosystem": "maven", "package": "io.netty:netty-handler", "version": "4.1.100.Final", "direct": True}
            ],
        },
    ]

    scan1 = run_incremental_inventory_scan(
        finos_cfg,
        initial_repos,
        checked_at="2026-11-01T00:00:00Z",
    )
    assert scan1["measurements"]["cache_misses"] == 2
    assert scan1["measurements"]["cache_hits"] == 0

    # Warm scan with:
    # - R1 having a new commit SHA ("aaa222" — README-only change!) but IDENTICAL dependency_files_sha256 ("hash-pom-1")
    # - R2 renamed to "finos/legend-core" with unchanged commit SHA ("bbb222")
    # - R3 inaccessible
    warm_repos = [
        {
            "repo_id": "R1",
            "full_name": "finos/Alloy",
            "commit_sha": "aaa222-readme-only",
            "dependency_files": [{"path": "pom.xml", "sha256": "hash-pom-1"}],
            "extracted_edges": [],  # Should not even be read because cache hits!
        },
        {
            "repo_id": "R2",
            "full_name": "finos/legend-core",
            "commit_sha": "bbb222",
            "dependency_files": [{"path": "pom.xml", "sha256": "hash-pom-2"}],
            "extracted_edges": [],
        },
        {
            "repo_id": "R3",
            "full_name": "finos/private-gate",
            "status": "inaccessible",
        },
    ]
    scan2 = run_incremental_inventory_scan(
        finos_cfg,
        warm_repos,
        previous_inventory_cache=scan1,
        checked_at="2026-11-02T00:00:00Z",
    )
    assert scan2["measurements"]["cache_hits"] == 2
    assert scan2["measurements"]["cache_misses"] == 0
    # Distinguishes branch_checked_at from dependency_extracted_at!
    assert scan2["repositories"]["finos/Alloy"]["branch_checked_at"] == "2026-11-02T00:00:00Z"
    assert scan2["repositories"]["finos/Alloy"]["dependency_extracted_at"] == "2026-11-01T00:00:00Z"
    assert scan2["membership_changes"]["renamed"] == [{"from": "finos/legend-engine", "to": "finos/legend-core", "repo_id": "R2"}]
    assert scan2["membership_changes"]["inaccessible"] == ["finos/private-gate"]

    # Parser/extractor version bump invalidates cache and forces re-extraction
    scan3 = run_incremental_inventory_scan(
        finos_cfg,
        initial_repos,
        previous_inventory_cache=scan1,
        extractor_version="extract_org/2026.11.2-bumped",
        checked_at="2026-11-03T00:00:00Z",
    )
    assert scan3["measurements"]["cache_misses"] == 2

    # Unexpected scope shrink (> 20%) raises RuntimeError
    try:
        run_incremental_inventory_scan(
            finos_cfg,
            [initial_repos[0]],
            previous_inventory_cache=scan1,
            max_allowed_shrink_ratio=0.20,
        )
        raise AssertionError("Expected RuntimeError on 50% repository shrink")
    except RuntimeError as exc:
        assert "shrink" in str(exc).lower()


def test_cross_collection_osv_deduplication_pagination_negative_cache_expiry_and_non_cve_preservation():
    cfg = load_collections_config(DEFAULT_COLLECTIONS_CONFIG_PATH)
    finos_cfg = cfg["collections"][0]
    labs_cfg = cfg["collections"][1]

    # Both FINOS and FINOS Labs share spring-web@5.3.20; FINOS also has unresolved range lodash@^4.17.0 and unsupported conan
    finos_inv = run_incremental_inventory_scan(
        finos_cfg,
        [
            {
                "repo_id": "F1",
                "full_name": "finos/app-a",
                "commit_sha": "c1",
                "dependency_files": [{"path": "pom.xml", "sha256": "h1"}],
                "extracted_edges": [
                    {"ecosystem": "maven", "package": "org.springframework:spring-web", "version": "5.3.20"},
                    {"ecosystem": "npm", "package": "lodash", "version": "^4.17.0"},
                    {"ecosystem": "conan", "package": "openssl", "version": "3.0.1"},
                ],
            }
        ],
    )
    labs_inv = run_incremental_inventory_scan(
        labs_cfg,
        [
            {
                "repo_id": "L1",
                "full_name": "finos-labs/agent-sandbox",
                "commit_sha": "c2",
                "dependency_files": [{"path": "pom.xml", "sha256": "h2"}],
                "extracted_edges": [
                    {"ecosystem": "maven", "package": "org.springframework:spring-web", "version": "5.3.20"},
                    {"ecosystem": "pypi", "package": "urllib3", "version": "2.0.7"},
                ],
            }
        ],
    )

    batch_map = {
        "org.springframework:spring-web@5.3.20": [{"id": "GHSA-spring-1", "modified": "2026-10-01T00:00:00Z"}],
        "org.springframework:spring-web@5.3.20#page2": [
            {"id": "GHSA-non-cve-only", "modified": "2026-10-02T00:00:00Z"},
            {"id": "GHSA-withdrawn-1", "modified": "2026-10-03T00:00:00Z"},
        ],
        "urllib3@2.0.7": [],  # Negative result initially
    }
    details_map = {
        "GHSA-spring-1": {
            "id": "GHSA-spring-1",
            "modified": "2026-10-01T00:00:00Z",
            "aliases": ["CVE-2024-22243"],
            "summary": "Spring Web URL parsing vulnerability",
            "affected": [{"package": {"ecosystem": "Maven", "name": "org.springframework:spring-web"}, "versions": ["5.3.20"]}],
        },
        "GHSA-non-cve-only": {
            "id": "GHSA-non-cve-only",
            "modified": "2026-10-02T00:00:00Z",
            "aliases": [],
            "summary": "Advisory without CVE alias",
            "affected": [{"package": {"ecosystem": "Maven", "name": "org.springframework:spring-web"}, "versions": ["5.3.20"]}],
        },
        "GHSA-withdrawn-1": {
            "id": "GHSA-withdrawn-1",
            "modified": "2026-10-03T00:00:00Z",
            "withdrawn": "2026-10-10T00:00:00Z",
            "aliases": ["CVE-2024-99999"],
            "affected": [],
        },
    }

    client = FakeOsvClient(batch_map, details_map)
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "vulns.db"
        res1 = resolve_inventory_scoped_osv_across_collections(
            [finos_inv, labs_inv],
            client,
            queried_at="2026-11-06T00:00:00Z",
            sqlite_db_path=db_path,
        )
        # Shared spring-web@5.3.20 + urllib3@2.0.7 = 2 unique exact package versions queried once across both collections!
        assert res1["unique_exact_packages_queried_across_collections"] == 2
        assert res1["withdrawn_advisories_filtered"] == ["GHSA-withdrawn-1"]

        # Both collections receive attributed findings
        finos_res = res1["per_collection"]["finos-github-org"]
        labs_res = res1["per_collection"]["finos-labs"]
        assert len(finos_res["cve_findings"]) == 1
        assert len(finos_res["non_cve_findings"]) == 1
        assert len(labs_res["cve_findings"]) == 1
        assert len(labs_res["non_cve_findings"]) == 1

        # Unresolved range and unsupported ecosystem are explicitly marked unknown, NEVER clean!
        assert len(finos_res["unresolved_range_edges"]) == 1
        assert finos_res["unresolved_range_edges"][0]["assessment_status"] == "unknown_unresolved_range"
        assert len(finos_res["unsupported_ecosystem_edges"]) == 1
        assert finos_res["unsupported_ecosystem_edges"][0]["assessment_status"] == "unknown_unsupported_ecosystem"

        # Warm run 1 hour later reuses query cache (0 new batch calls, 0 new detail calls)
        res_warm = resolve_inventory_scoped_osv_across_collections(
            [finos_inv, labs_inv],
            client,
            osv_cache=res1["updated_cache"],
            queried_at="2026-11-06T01:00:00Z",
            security_freshness_ttl_seconds=86400,
        )
        assert res_warm["measurements"]["osv_batch_requests"] == 0
        assert res_warm["measurements"]["osv_detail_requests"] == 0
        assert res_warm["measurements"]["query_cache_hits"] == 2

        # After 25 hours (> 24h TTL), negative-cache expiry requeries urllib3@2.0.7 and detects a newly disclosed advisory!
        # Meanwhile unchanged GHSA-spring-1 and GHSA-non-cve-only reuse cached advisory details!
        batch_map["urllib3@2.0.7"] = [{"id": "GHSA-urllib3-new", "modified": "2026-11-07T00:00:00Z"}]
        details_map["GHSA-urllib3-new"] = {
            "id": "GHSA-urllib3-new",
            "modified": "2026-11-07T00:00:00Z",
            "aliases": ["CVE-2026-77777"],
            "summary": "Newly disclosed urllib3 vulnerability on unchanged inventory",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3"}, "versions": ["2.0.7"]}],
        }
        res_expired = resolve_inventory_scoped_osv_across_collections(
            [finos_inv, labs_inv],
            client,
            osv_cache=res1["updated_cache"],
            queried_at="2026-11-07T02:00:00Z",
            security_freshness_ttl_seconds=86400,
        )
        assert res_expired["measurements"]["detail_cache_hits"] == 3
        assert res_expired["measurements"]["osv_detail_requests"] == 1
        assert len(res_expired["per_collection"]["finos-labs"]["cve_findings"]) == 2


def test_canonical_hash_receipt_comparison_modes_and_safe_publication_rollback():
    ds_base = {
        "meta": {"scope_name": "finos-labs", "generated_at": "2026-11-05T00:00:00Z", "coverage": {"repositories": 10}},
        "libraries": [{"id": "maven|org.springframework|spring-web|5.3.20", "cves": [{"cve_id": "CVE-2024-22243"}]}],
    }
    ds_same_semantic = copy.deepcopy(ds_base)
    ds_same_semantic["meta"]["generated_at"] = "2026-11-06T12:34:56Z"

    # Volatile run timestamp does not change canonical content_sha256!
    assert compute_canonical_assessment_sha256(ds_base) == compute_canonical_assessment_sha256(ds_same_semantic)

    sources = [{"name": "osera_openvex", "version": "161", "retrieved_at": "2026-11-06T00:00:00Z", "sha256": "abc123"}]
    artifacts = [{"kind": "dataset", "path": "data/finos-labs.json"}]

    rec1 = build_assessment_receipt(
        collection_id="finos-labs",
        dataset=ds_base,
        inventory_snapshot_id="inv-1",
        evidence_snapshot_ids={"osv": "osv-1", "osera_openvex": "vex-161"},
        sources=sources,
        artifacts=artifacts,
    )

    # Mode 1: Evidence change against same inventory
    ds_ev_changed = copy.deepcopy(ds_base)
    ds_ev_changed["libraries"][0]["cves"].append({"cve_id": "CVE-2024-22259"})
    rec_ev = build_assessment_receipt(
        collection_id="finos-labs",
        dataset=ds_ev_changed,
        inventory_snapshot_id="inv-1",
        evidence_snapshot_ids={"osv": "osv-2", "osera_openvex": "vex-161"},
        sources=sources,
        artifacts=artifacts,
    )
    cmp_ev = compare_assessment_snapshots(rec1, ds_base, rec_ev, ds_ev_changed)
    assert cmp_ev["comparison_mode"] == "evidence_changes_only"
    assert cmp_ev["newly_observed_cves"] == ["CVE-2024-22259"]

    # Mode 2: Inventory change under same evidence
    ds_inv_changed = copy.deepcopy(ds_base)
    ds_inv_changed["libraries"].append({"id": "pypi||urllib3|2.0.7", "cves": [{"cve_id": "CVE-2026-77777"}]})
    rec_inv = build_assessment_receipt(
        collection_id="finos-labs",
        dataset=ds_inv_changed,
        inventory_snapshot_id="inv-2",
        evidence_snapshot_ids={"osv": "osv-1", "osera_openvex": "vex-161"},
        sources=sources,
        artifacts=artifacts,
    )
    cmp_inv = compare_assessment_snapshots(rec1, ds_base, rec_inv, ds_inv_changed)
    assert cmp_inv["comparison_mode"] == "inventory_changes_only"
    assert cmp_inv["newly_affected_libraries"] == ["pypi||urllib3|2.0.7"]

    # Safe publication & mid-publication rollback test
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ds_path = tmp / "finos-labs.json"
        cov_path = tmp / "finos-labs-coverage.json"
        rec_path = tmp / "finos-labs.receipt.json"

        publish_collection_artifacts_safely(
            dataset=ds_base,
            coverage_report={"repositories": 10},
            receipt=rec1,
            dataset_dest=ds_path,
            coverage_dest=cov_path,
            receipt_dest=rec_path,
        )
        orig_bytes = ds_path.read_bytes()

        # Inject mid-publication failure -> must roll back ds_path to orig_bytes!
        try:
            publish_collection_artifacts_safely(
                dataset=ds_ev_changed,
                coverage_report={"repositories": 10},
                receipt=rec_ev,
                dataset_dest=ds_path,
                coverage_dest=cov_path,
                receipt_dest=rec_path,
                inject_mid_publish_failure=True,
            )
            raise AssertionError("Expected RuntimeError on injected mid-publication failure")
        except RuntimeError:
            pass
        assert ds_path.read_bytes() == orig_bytes


def test_pipeline_status_updates_stale_running_reconciliation_and_secret_redaction():
    status_doc = json.loads(DEFAULT_PIPELINE_STATUS_PATH.read_text(encoding="utf-8"))

    # Inject a stale running attempt on finos-labs started 5 hours ago
    status_doc["pipelines"][1]["latest_attempt"] = {
        "run_id": "111",
        "outcome": "running",
        "started_at": "2026-11-05T18:00:00Z",
    }

    # Update finos-github-org with a failed attempt containing a GitHub token and local path
    updated = update_pipeline_status_document(
        status_doc,
        collection_id="finos-github-org",
        attempt={
            "run_id": "222",
            "outcome": "failed",
            "started_at": "2026-11-06T00:00:00Z",
            "completed_at": "2026-11-06T00:01:00Z",
        },
        failure_summary="Failed at /Users/alice/secret/repo with token ghp_1234567890abcdefghijklmnop",
        checked_at="2026-11-06T00:02:00Z",
    )

    by_cid = {p["collection_id"]: p for p in updated["pipelines"]}
    # Stale running record on finos-labs was reconciled to 'stale_unknown'
    assert by_cid["finos-labs"]["latest_attempt"]["outcome"] == "stale_unknown"

    # Failed attempt on finos-github-org retained previous published snapshot and redacted token/path
    finos_pipe = by_cid["finos-github-org"]
    assert finos_pipe["publication_state"] == "previous_snapshot_retained_after_failure"
    assert finos_pipe["previous_valid_snapshot_retained"] is True
    assert finos_pipe["currently_published_snapshot"]["snapshot_id"] == "finos-github-org-20261103"
    assert "ghp_" not in finos_pipe["failure_summary"]
    assert "/Users/" not in finos_pipe["failure_summary"]
    assert "[REDACTED_CREDENTIAL]" in finos_pipe["failure_summary"]

    # Candidate awaiting review on finos-labs does not appear as published until promoted
    updated2 = update_pipeline_status_document(
        updated,
        collection_id="finos-labs",
        attempt={"run_id": "333", "outcome": "succeeded"},
        validated_candidate={"snapshot_id": "finos-labs-cand-1", "content_sha256": "deadbeef"},
        promote_to_published=False,
        pending_pr_url="https://github.com/finos-osera/risk-navigator/pull/99",
        checked_at="2026-11-06T00:10:00Z",
    )
    labs_pipe = next(p for p in updated2["pipelines"] if p["collection_id"] == "finos-labs")
    assert labs_pipe["publication_state"] == "refresh_succeeded_pr_awaiting_review"
    assert labs_pipe["currently_published_snapshot"] is None
    assert labs_pipe["latest_validated_candidate"]["snapshot_id"] == "finos-labs-cand-1"


class IncrementalRefreshPipelineTestCase(unittest.TestCase):
    def test_all(self):
        test_collections_config_and_incremental_inventory_reuse_readme_change_and_shrink_guard()
        test_cross_collection_osv_deduplication_pagination_negative_cache_expiry_and_non_cve_preservation()
        test_canonical_hash_receipt_comparison_modes_and_safe_publication_rollback()
        test_pipeline_status_updates_stale_running_reconciliation_and_secret_redaction()


if __name__ == "__main__":
    unittest.main()

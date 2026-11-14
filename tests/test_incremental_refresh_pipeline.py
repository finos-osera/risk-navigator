import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import incremental_refresh_pipeline as pipeline
from incremental_refresh_pipeline import (
    DEFAULT_COLLECTIONS_CONFIG_PATH,
    DEFAULT_PIPELINE_STATUS_PATH,
    ROOT_DIR,
    build_assessment_receipt,
    build_deployment_manifest,
    build_public_pipeline_status_from_artifacts,
    compare_assessment_snapshots,
    compute_canonical_assessment_sha256,
    load_collections_config,
    main as cli_main,
    publish_collection_artifacts_safely,
    reassess_inventory_with_refreshed_evidence,
    refresh_shared_evidence_sources_conditionally,
    resolve_inventory_scoped_osv_across_collections,
    run_incremental_inventory_scan,
    sanitize_public_failure_summary,
    update_pipeline_status_document,
    validate_assessment_receipt,
    validate_public_pipeline_status_provenance,
    verify_offline_replay_determinism,
    verify_promotion_candidate_not_stale,
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

    warm_repos = [
        {
            "repo_id": "R1",
            "full_name": "finos/Alloy",
            "commit_sha": "aaa222-readme-only",
            "dependency_files": [{"path": "pom.xml", "sha256": "hash-pom-1"}],
            "extracted_edges": [],
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
    assert scan2["repositories"]["finos/Alloy"]["branch_checked_at"] == "2026-11-02T00:00:00Z"
    assert scan2["repositories"]["finos/Alloy"]["dependency_extracted_at"] == "2026-11-01T00:00:00Z"
    assert scan2["membership_changes"]["renamed"] == [{"from": "finos/legend-engine", "to": "finos/legend-core", "repo_id": "R2"}]
    assert scan2["membership_changes"]["inaccessible"] == ["finos/private-gate"]

    scan3 = run_incremental_inventory_scan(
        finos_cfg,
        initial_repos,
        previous_inventory_cache=scan1,
        extractor_version="extract_org/2026.11.2-bumped",
        checked_at="2026-11-03T00:00:00Z",
    )
    assert scan3["measurements"]["cache_misses"] == 2

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
        "urllib3@2.0.7": [],
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
        assert res1["unique_exact_packages_queried_across_collections"] == 2
        assert res1["withdrawn_advisories_filtered"] == ["GHSA-withdrawn-1"]

        finos_res = res1["per_collection"]["finos-github-org"]
        labs_res = res1["per_collection"]["finos-labs"]
        assert len(finos_res["cve_findings"]) == 1
        assert len(finos_res["non_cve_findings"]) == 1
        assert len(labs_res["cve_findings"]) == 1
        assert len(labs_res["non_cve_findings"]) == 1

        assert len(finos_res["unresolved_range_edges"]) == 1
        assert finos_res["unresolved_range_edges"][0]["assessment_status"] == "unknown_unresolved_range"
        assert len(finos_res["unsupported_ecosystem_edges"]) == 1
        assert finos_res["unsupported_ecosystem_edges"][0]["assessment_status"] == "unknown_unsupported_ecosystem"

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


def test_omitted_timestamps_use_current_clock_and_expire_positive_and_negative_osv_cache():
    """Verify @DovOps Item 1: advancing the clock without supplying explicit timestamps expires positive & negative cache entries."""
    cfg = load_collections_config(DEFAULT_COLLECTIONS_CONFIG_PATH)
    finos_cfg = cfg["collections"][0]

    with mock.patch.object(pipeline, "_current_utc_iso", return_value="2026-11-06T00:05:00Z"):
        inv = run_incremental_inventory_scan(
            finos_cfg,
            [
                {
                    "repo_id": "R1",
                    "full_name": "finos/clock-test",
                    "commit_sha": "sha1",
                    "dependency_files": [{"path": "package.json", "sha256": "p1"}],
                    "extracted_edges": [
                        {"ecosystem": "npm", "package": "vuln-pkg", "version": "1.0.0"},
                        {"ecosystem": "npm", "package": "clean-pkg", "version": "1.0.0"},
                    ],
                }
            ],
        )
        assert inv["branch_checked_at"] == "2026-11-06T00:05:00Z"

        batch_map = {
            "vuln-pkg@1.0.0": [{"id": "GHSA-pos-1", "modified": "2026-11-01T00:00:00Z"}],
            "clean-pkg@1.0.0": [],
        }
        details_map = {
            "GHSA-pos-1": {
                "id": "GHSA-pos-1",
                "modified": "2026-11-01T00:00:00Z",
                "aliases": ["CVE-2026-11111"],
                "summary": "Initial vulnerability on vuln-pkg",
                "affected": [{"package": {"ecosystem": "npm", "name": "vuln-pkg"}, "versions": ["1.0.0"]}],
            }
        }
        client = FakeOsvClient(batch_map, details_map)

        # Call 1 at Nov 6 00:05Z WITHOUT explicit queried_at
        res_nov6 = resolve_inventory_scoped_osv_across_collections([inv], client)
        assert res_nov6["queried_at"] == "2026-11-06T00:05:00Z"
        assert res_nov6["measurements"]["osv_batch_requests"] == 1
        assert res_nov6["measurements"]["query_cache_hits"] == 0
        assert len(res_nov6["per_collection"]["finos-github-org"]["cve_findings"]) == 1

    # Advance clock by 2 hours on Nov 6 -> both positive and negative entries hit cache
    with mock.patch.object(pipeline, "_current_utc_iso", return_value="2026-11-06T02:05:00Z"):
        res_nov6_later = resolve_inventory_scoped_osv_across_collections(
            [inv],
            client,
            osv_cache=res_nov6["updated_cache"],
        )
        assert res_nov6_later["queried_at"] == "2026-11-06T02:05:00Z"
        assert res_nov6_later["measurements"]["osv_batch_requests"] == 0
        assert res_nov6_later["measurements"]["query_cache_hits"] == 2

    # Advance clock to November 20 without supplying queried_at after a Nov 10 disclosure on clean-pkg AND an update on vuln-pkg
    batch_map["clean-pkg@1.0.0"] = [{"id": "GHSA-nov10-disclosed", "modified": "2026-11-10T12:00:00Z"}]
    batch_map["vuln-pkg@1.0.0"] = [
        {"id": "GHSA-pos-1", "modified": "2026-11-01T00:00:00Z"},
        {"id": "GHSA-pos-2", "modified": "2026-11-12T00:00:00Z"},
    ]
    details_map["GHSA-nov10-disclosed"] = {
        "id": "GHSA-nov10-disclosed",
        "modified": "2026-11-10T12:00:00Z",
        "aliases": ["CVE-2026-22222"],
        "summary": "Disclosed Nov 10 on previously clean package",
        "affected": [{"package": {"ecosystem": "npm", "name": "clean-pkg"}, "versions": ["1.0.0"]}],
    }
    details_map["GHSA-pos-2"] = {
        "id": "GHSA-pos-2",
        "modified": "2026-11-12T00:00:00Z",
        "aliases": ["CVE-2026-33333"],
        "summary": "Second advisory on vuln-pkg",
        "affected": [{"package": {"ecosystem": "npm", "name": "vuln-pkg"}, "versions": ["1.0.0"]}],
    }

    with mock.patch.object(pipeline, "_current_utc_iso", return_value="2026-11-20T00:05:00Z"):
        res_nov20 = resolve_inventory_scoped_osv_across_collections(
            [inv],
            client,
            osv_cache=res_nov6_later["updated_cache"],
        )
        assert res_nov20["queried_at"] == "2026-11-20T00:05:00Z"
        assert res_nov20["measurements"]["query_cache_hits"] == 0
        assert res_nov20["measurements"]["osv_batch_requests"] == 1
        cves_found = sorted(
            cve
            for f in res_nov20["per_collection"]["finos-github-org"]["cve_findings"]
            for cve in f["cve_aliases"]
        )
        assert cves_found == ["CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"]


def test_canonical_hash_receipt_comparison_modes_and_safe_publication_rollback():
    """Verify @DovOps Item 2: failed first publication, replacement of existing files, and mixed existing/new targets restore full pre-publication state."""
    ds_base = {
        "meta": {"scope_name": "finos-labs", "generated_at": "2026-11-05T00:00:00Z", "coverage": {"repositories": 10}},
        "libraries": [{"id": "maven|org.springframework|spring-web|5.3.20", "cves": [{"cve_id": "CVE-2024-22243"}]}],
    }
    ds_same_semantic = copy.deepcopy(ds_base)
    ds_same_semantic["meta"]["generated_at"] = "2026-11-06T12:34:56Z"

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

    # Case 1: Failed FIRST publication (all destinations initially absent -> all removed on rollback!)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ds_path = tmp / "finos-labs.json"
        cov_path = tmp / "finos-labs-coverage.json"
        rec_path = tmp / "finos-labs.receipt.json"

        try:
            publish_collection_artifacts_safely(
                dataset=ds_base,
                coverage_report={"repositories": 10},
                receipt=rec1,
                dataset_dest=ds_path,
                coverage_dest=cov_path,
                receipt_dest=rec_path,
                inject_mid_publish_failure=True,
            )
            raise AssertionError("Expected RuntimeError on failed first publication")
        except RuntimeError:
            pass

        assert not ds_path.exists(), "First-publication rollback must remove newly created dataset.json"
        assert not cov_path.exists(), "First-publication rollback must not leave coverage.json"
        assert not rec_path.exists(), "First-publication rollback must not leave receipt.json"

        # Now succeed on initial publication
        publish_collection_artifacts_safely(
            dataset=ds_base,
            coverage_report={"repositories": 10},
            receipt=rec1,
            dataset_dest=ds_path,
            coverage_dest=cov_path,
            receipt_dest=rec_path,
        )
        orig_ds_bytes = ds_path.read_bytes()
        orig_cov_bytes = cov_path.read_bytes()
        orig_rec_bytes = rec_path.read_bytes()

        # Case 2: Failed replacement of existing files -> restores all existing files byte-for-byte
        try:
            publish_collection_artifacts_safely(
                dataset=ds_ev_changed,
                coverage_report={"repositories": 99},
                receipt=rec_ev,
                dataset_dest=ds_path,
                coverage_dest=cov_path,
                receipt_dest=rec_path,
                inject_mid_publish_failure=True,
            )
            raise AssertionError("Expected RuntimeError on injected mid-publication failure")
        except RuntimeError:
            pass
        assert ds_path.read_bytes() == orig_ds_bytes
        assert cov_path.read_bytes() == orig_cov_bytes
        assert rec_path.read_bytes() == orig_rec_bytes

    # Case 3: Mixed existing and new targets (dataset exists, coverage & receipt initially absent; fail at step 2)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        ds_path = tmp / "finos-labs.json"
        cov_path = tmp / "finos-labs-coverage.json"
        rec_path = tmp / "finos-labs.receipt.json"

        ds_path.write_text('{"preexisting": true}\n', encoding="utf-8")
        preexisting_ds_bytes = ds_path.read_bytes()

        try:
            publish_collection_artifacts_safely(
                dataset=ds_ev_changed,
                coverage_report={"repositories": 12},
                receipt=rec_ev,
                dataset_dest=ds_path,
                coverage_dest=cov_path,
                receipt_dest=rec_path,
                inject_failure_at_step=2,  # Fails after overwriting ds_path (idx 0) and creating cov_path (idx 1)
            )
            raise AssertionError("Expected RuntimeError on mixed target failure at step 2")
        except RuntimeError:
            pass

        assert ds_path.exists() and ds_path.read_bytes() == preexisting_ds_bytes
        assert not cov_path.exists(), "Newly created coverage report must be unlinked on rollback"
        assert not rec_path.exists(), "Receipt must remain absent on rollback"


FIXTURE_PIPELINE_ROOT = ROOT_DIR / "tests" / "fixtures" / "pipeline"
FIXTURE_PIPELINE_STATUS_PATH = FIXTURE_PIPELINE_ROOT / "data" / "pipeline-status.json"


def test_pipeline_status_updates_stale_running_reconciliation_and_secret_redaction():
    """Verify controlled default failure messages and full Authorization/credential/path redaction across serialized status JSON."""
    status_doc = json.loads(FIXTURE_PIPELINE_STATUS_PATH.read_text(encoding="utf-8"))
    orig_finos_snap_id = status_doc["pipelines"][0]["currently_published_snapshot"]["snapshot_id"]

    status_doc["pipelines"][1]["latest_attempt"] = {
        "run_id": "111",
        "outcome": "running",
        "started_at": "2026-11-05T18:00:00Z",
    }

    synthetic_error = (
        "GET https://ci-user:s3cr3tPass!@feed.internal.example/v1/vulns?api_key=ak_live_998877&token=tok_abc123 "
        "Authorization: Bearer SYNTHETIC_SECRET_123456 "
        "Authorization: Basic dXNlcjpzZWNyZXRfcGFzc3dvcmQ= "
        "'Authorization': 'Bearer QUOTED_SECRET_987654' "
        "Proxy-Authorization: CustomScheme CUSTOM_SECRET_55555 "
        "failed while reading /home/runner/work/risk-navigator/risk-navigator/data/local/raw "
        "and /Users/alice/secret/repo with ghp_1234567890abcdefghijklmnop and C:\\Users\\runneradmin\\work\\secret.json"
    )
    forbidden_secrets = (
        "SYNTHETIC_SECRET_123456",
        "dXNlcjpzZWNyZXRfcGFzc3dvcmQ",
        "QUOTED_SECRET_987654",
        "CUSTOM_SECRET_55555",
        "ci-user",
        "s3cr3tPass",
        "ak_live_998877",
        "tok_abc123",
        "ghp_1234567890abcdefghijklmnop",
        "/home/runner/work",
        "/Users/alice",
        "C:\\Users\\runneradmin",
    )

    # 1. Default behavior: controlled public failure message (zero raw upstream text exposed)
    updated_default = update_pipeline_status_document(
        status_doc,
        collection_id="finos-github-org",
        attempt={
            "run_id": "222",
            "outcome": "failed",
            "started_at": "2026-11-06T00:00:00Z",
            "completed_at": "2026-11-06T00:01:00Z",
        },
        failure_summary="Authorization: Bearer SYNTHETIC_SECRET_123456",
        checked_at="2026-11-06T00:02:00Z",
    )
    serialized_default = json.dumps(updated_default)
    assert "SYNTHETIC_SECRET_123456" not in serialized_default
    by_cid_default = {p["collection_id"]: p for p in updated_default["pipelines"]}
    assert by_cid_default["finos-labs"]["latest_attempt"]["outcome"] == "stale_unknown"
    assert by_cid_default["finos-labs"]["failure_code"] == "stale_running_timeout"
    assert by_cid_default["finos-github-org"]["failure_code"] == "upstream_feed_request_failed"
    assert by_cid_default["finos-github-org"]["failure_summary"] == (
        "Upstream advisory or metadata feed request failed; retaining previous published snapshot."
    )
    assert by_cid_default["finos-github-org"]["currently_published_snapshot"]["snapshot_id"] == orig_finos_snap_id

    # 2. Explicit raw sanitization mode (prefer_controlled_failure_message=False): full header & scheme value redacted
    assert (
        sanitize_public_failure_summary("Authorization: Bearer SYNTHETIC_SECRET_123456", prefer_controlled_message=False)
        == "Authorization: [REDACTED_CREDENTIAL]"
    )
    assert (
        sanitize_public_failure_summary("Authorization: Basic dXNlcjpzZWNyZXRfcGFzc3dvcmQ=", prefer_controlled_message=False)
        == "Authorization: [REDACTED_CREDENTIAL]"
    )

    updated_raw = update_pipeline_status_document(
        status_doc,
        collection_id="finos-github-org",
        attempt={
            "run_id": "223",
            "outcome": "failed",
            "started_at": "2026-11-06T00:00:00Z",
            "completed_at": "2026-11-06T00:01:00Z",
        },
        failure_summary=synthetic_error,
        prefer_controlled_failure_message=False,
        checked_at="2026-11-06T00:03:00Z",
    )
    serialized_raw = json.dumps(updated_raw)
    for forbidden in forbidden_secrets:
        assert forbidden not in serialized_raw, f"Leaked sensitive substring {forbidden!r} in serialized public status"

    finos_raw = next(p for p in updated_raw["pipelines"] if p["collection_id"] == "finos-github-org")
    assert finos_raw["publication_state"] == "previous_snapshot_retained_after_failure"
    assert finos_raw["previous_valid_snapshot_retained"] is True
    assert "[REDACTED_CREDENTIAL]" in finos_raw["failure_summary"]

    updated2 = update_pipeline_status_document(
        updated_default,
        collection_id="finos-labs",
        attempt={"run_id": "333", "outcome": "succeeded"},
        validated_candidate={"snapshot_id": "finos-labs-cand-1", "content_sha256": "d" * 64},
        promote_to_published=False,
        pending_pr_url="https://github.com/finos-osera/risk-navigator/pull/99",
        checked_at="2026-11-06T00:10:00Z",
    )
    labs_pipe = next(p for p in updated2["pipelines"] if p["collection_id"] == "finos-labs")
    assert labs_pipe["publication_state"] == "refresh_succeeded_pr_awaiting_review"
    assert labs_pipe["currently_published_snapshot"] is None
    assert labs_pipe["latest_validated_candidate"]["snapshot_id"] == "finos-labs-cand-1"


def test_public_pipeline_status_provenance_same_date_uniqueness_and_historical_honesty():
    """Verify fixture provenance, unique content-bound snapshot IDs on same date, synthetic-hash rejection, and honest historical state."""
    # Phase 1 Foundation invariant: illustrative status/receipts live in tests/fixtures/pipeline, not live data/
    assert not DEFAULT_PIPELINE_STATUS_PATH.exists(), "Live data/pipeline-status.json must remain absent in Phase 1 foundation PR"
    assert not (ROOT_DIR / "data" / "receipts" / "finos-github-org.receipt.json").exists()

    status_doc = json.loads(FIXTURE_PIPELINE_STATUS_PATH.read_text(encoding="utf-8"))
    errors = validate_public_pipeline_status_provenance(status_doc, root_dir=FIXTURE_PIPELINE_ROOT)
    assert errors == [], f"Unexpected provenance errors in fixture pipeline-status.json: {errors}"

    # Tampered receipt link or non-content-bound date-only snapshot_id is rejected
    tampered = copy.deepcopy(status_doc)
    tampered["pipelines"][0]["currently_published_snapshot"]["receipt_url"] = "../data/receipts/nonexistent.receipt.json"
    tampered_errors = validate_public_pipeline_status_provenance(tampered, root_dir=FIXTURE_PIPELINE_ROOT)
    assert any("does not exist on disk" in e for e in tampered_errors)

    date_only_tampered = copy.deepcopy(status_doc)
    date_only_tampered["pipelines"][0]["currently_published_snapshot"]["snapshot_id"] = "finos-github-org-20261105"
    date_only_errors = validate_public_pipeline_status_provenance(date_only_tampered, root_dir=FIXTURE_PIPELINE_ROOT)
    assert any("not immutably bound to content_sha256" in e for e in date_only_errors)

    # Reproduction: two different datasets on the SAME inventory date receive distinct immutable snapshot IDs
    with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
        for idx, tmp_str in enumerate((tmp_a, tmp_b)):
            root = Path(tmp_str)
            (root / "data").mkdir(parents=True, exist_ok=True)
            ds_payload = json.loads((FIXTURE_PIPELINE_ROOT / "data" / "finos-github-org.json").read_text(encoding="utf-8"))
            cov_payload = json.loads((FIXTURE_PIPELINE_ROOT / "data" / "finos-coverage.json").read_text(encoding="utf-8"))
            cov_payload["inventory_completed_at"] = "2026-11-03T06:00:00Z"
            ds_payload["meta"]["inventory_scanned_at"] = "2026-11-03T06:00:00Z"
            if idx == 1:
                ds_payload["libraries"][0]["cves"].append({"cve_id": "CVE-2026-90909", "summary": "Second dataset diff"})
            (root / "data" / "finos-github-org.json").write_text(json.dumps(ds_payload), encoding="utf-8")
            (root / "data" / "finos-coverage.json").write_text(json.dumps(cov_payload), encoding="utf-8")

        st_a = build_public_pipeline_status_from_artifacts(root_dir=Path(tmp_a), checked_at="2026-11-06T00:00:00Z", write_receipts=True)
        st_b = build_public_pipeline_status_from_artifacts(root_dir=Path(tmp_b), checked_at="2026-11-06T00:00:00Z", write_receipts=True)
        assert validate_public_pipeline_status_provenance(st_a, root_dir=Path(tmp_a)) == []
        assert validate_public_pipeline_status_provenance(st_b, root_dir=Path(tmp_b)) == []

        snap_a = st_a["pipelines"][0]["currently_published_snapshot"]
        snap_b = st_b["pipelines"][0]["currently_published_snapshot"]
        assert snap_a["snapshot_id"].startswith("finos-github-org-20261103-")
        assert snap_b["snapshot_id"].startswith("finos-github-org-20261103-")
        assert snap_a["snapshot_id"] != snap_b["snapshot_id"]
        assert snap_a["content_sha256"] != snap_b["content_sha256"]

        # Synthetic timestamp-wrapper source digest is rejected by receipt & status provenance validators
        rec_a_path = Path(tmp_a) / "data" / "receipts" / "finos-github-org.receipt.json"
        rec_a_doc = json.loads(rec_a_path.read_text(encoding="utf-8"))
        rec_a_doc["sources"][2]["sha256"] = pipeline._sha256_json({"kev_fetched_at": rec_a_doc["sources"][2]["retrieved_at"]})
        rec_a_path.write_text(json.dumps(rec_a_doc), encoding="utf-8")
        synth_errors = validate_public_pipeline_status_provenance(st_a, root_dir=Path(tmp_a))
        assert any("synthetic timestamp" in e for e in synth_errors)

    # Historical repo artifacts without captured KEV/EPSS digests or run metadata are represented honestly (never hardcoded)
    with tempfile.TemporaryDirectory() as hist_tmp:
        hist_root = Path(hist_tmp)
        (hist_root / "data").mkdir(parents=True, exist_ok=True)
        (hist_root / "oss-risk" / "data").mkdir(parents=True, exist_ok=True)
        for rel in (
            "data/finos-github-org.json",
            "data/finos-coverage.json",
            "oss-risk/data/finos-osera-backpatch-scorecards.json",
            "oss-risk/data/finos-osera-backpatch-libraries.json",
        ):
            (hist_root / rel).write_bytes((ROOT_DIR / rel).read_bytes())

        hist_status = build_public_pipeline_status_from_artifacts(
            root_dir=hist_root,
            checked_at="2026-11-06T00:00:00Z",
            write_receipts=True,
        )
        hist_finos = hist_status["pipelines"][0]
        assert hist_finos["publication_state"] == "partial_historical_provenance"
        assert hist_finos["provenance_completeness"] == "partial_historical"
        assert hist_finos["latest_attempt"]["run_id"] is None
        assert hist_finos["latest_attempt"]["code_sha"] is None
        assert hist_finos["currently_published_snapshot"]["osera_openvex_version"] is None
        assert hist_finos["currently_published_snapshot"]["oss_risk_snapshot_id"] is None

        hist_rec = json.loads((hist_root / "data" / "receipts" / "finos-github-org.receipt.json").read_text(encoding="utf-8"))
        kev_entry = next(s for s in hist_rec["sources"] if s["name"] == "cisa-kev")
        assert kev_entry["sha256"] is None
        assert kev_entry["status"] == "unavailable_historical"

        # Default strict validator rejects partial_historical_provenance as verified public evidence
        strict_hist_errors = validate_public_pipeline_status_provenance(hist_status, root_dir=hist_root)
        assert any("partial_historical_provenance" in e for e in strict_hist_errors)
        assert validate_public_pipeline_status_provenance(hist_status, root_dir=hist_root, allow_partial_historical=True) == []

    # Clean empty directory initializes all collections as awaiting_initial_publication
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_status = build_public_pipeline_status_from_artifacts(
            root_dir=Path(tmpdir),
            checked_at="2026-11-06T00:00:00Z",
            write_receipts=False,
        )
        for pipe in empty_status["pipelines"]:
            assert pipe["publication_state"] == "awaiting_initial_publication"
            assert pipe["currently_published_snapshot"] is None


def test_conditional_shared_evidence_refresh_evidence_only_reassessment_and_offline_replay_cli():
    """Verify conditional shared-source refresh, obsolete-CVE removal + incomplete preservation on reassessment, replay, and CLI."""
    source_specs = {
        "osera_openvex": {"url": "https://feed.finos.org/openvex.json", "freshness_ttl_seconds": 86400},
        "cisa_kev": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    }
    observed_headers: dict[str, dict[str, str]] = {}

    def fetcher_initial(url: str, headers: dict[str, str]) -> dict:
        observed_headers[url] = copy.deepcopy(headers)
        if "openvex" in url:
            return {
                "status": 200,
                "etag": '"vex-etag-161"',
                "last_modified": "Wed, 05 Nov 2026 00:00:00 GMT",
                "payload": {"feed_version": 161, "statements": []},
            }
        return {
            "status": 200,
            "etag": '"kev-etag-1"',
            "payload": {"catalogVersion": "2026.11.05", "vulnerabilities": [{"cveID": "CVE-2024-22243"}]},
        }

    cond1 = refresh_shared_evidence_sources_conditionally(
        source_specs,
        fetcher_initial,
        checked_at="2026-11-05T12:00:00Z",
    )
    assert cond1["any_evidence_changed"] is True
    assert sorted(cond1["changed_sources"]) == ["cisa_kev", "osera_openvex"]

    def fetcher_conditional(url: str, headers: dict[str, str]) -> dict:
        observed_headers[url] = copy.deepcopy(headers)
        if "openvex" in url:
            assert headers.get("If-None-Match") == '"vex-etag-161"'
            return {"status": 304}
        return {
            "status": 200,
            "etag": '"kev-etag-2"',
            "payload": {
                "catalogVersion": "2026.11.06",
                "vulnerabilities": [{"cveID": "CVE-2024-22243"}, {"cveID": "CVE-2026-55555"}],
            },
        }

    cond2 = refresh_shared_evidence_sources_conditionally(
        source_specs,
        fetcher_conditional,
        previous_source_state=cond1["sources"],
        checked_at="2026-11-06T12:00:00Z",
    )
    assert cond2["any_evidence_changed"] is True
    assert cond2["changed_sources"] == ["cisa_kev"]
    assert cond2["measurements"]["not_modified_hits"] == 1
    assert cond2["sources"]["osera_openvex"]["changed"] is False

    # Evidence-only reassessment without re-crawling GitHub repositories
    base_ds = {
        "meta": {
            "scope_name": "finos-labs",
            "inventory_scanned_at": "2026-11-01T00:00:00Z",
            "vulnerabilities_queried_at": "2026-11-01T00:05:00Z",
            "counts": {"consumer_projects": 4, "distinct_cve_libraries": 1, "unique_cves": 1},
            "coverage": {"repositories": 4, "vulnerable_library_versions": 1, "unique_cves": 1},
        },
        "consumer_projects": [
            {
                "id": "finos-labs/app-1",
                "vulnerable_library_ids": ["maven|org.springframework|spring-web|5.3.20"],
                "vulnerable_library_count": 1,
            }
        ],
        "libraries": [
            {
                "id": "maven|org.springframework|spring-web|5.3.20",
                "namespace": "maven",
                "meta": "org.springframework",
                "proj": "spring-web",
                "release": "5.3.20",
                "cves": [{"cve_id": "CVE-2024-22243", "kev": False, "epss": 0.12}],
            }
        ],
    }
    base_rec = build_assessment_receipt(
        collection_id="finos-labs",
        dataset=base_ds,
        inventory_snapshot_id="finos-labs-inv-fixed",
        evidence_snapshot_ids={"osv": "osv-1", "kev": "kev-1"},
        sources=[{"name": "osv", "sha256": "a" * 64, "retrieved_at": "2026-11-01T00:05:00Z"}],
        artifacts=[{"role": "dataset", "path": "data/finos-labs.json"}],
        collector_commit="07ee91e7e264a530b7be987e40477fbb48d613af",
        generated_at="2026-11-01T00:10:00Z",
    )

    reassessed = reassess_inventory_with_refreshed_evidence(
        collection_id="finos-labs",
        baseline_dataset=base_ds,
        baseline_receipt=base_rec,
        refreshed_osv_collection_result={
            "evaluated_library_ids": ["maven|org.springframework|spring-web|5.3.20"],
            "cve_findings": [
                {
                    "library_id": "maven|org.springframework|spring-web|5.3.20",
                    "cve_aliases": ["CVE-2024-22243", "CVE-2026-55555"],
                    "summary": "New spring-web advisory",
                }
            ],
            "non_cve_findings": [{"library_id": "maven|org.springframework|spring-web|5.3.20", "advisory_id": "GHSA-no-cve"}],
        },
        kev_cve_ids={"CVE-2026-55555"},
        epss_by_cve={"CVE-2024-22243": 0.45, "CVE-2026-55555": 0.89},
        refreshed_evidence_snapshot_ids={"osv": "osv-2", "kev": "kev-2"},
        refreshed_sources=[{"name": "osv", "sha256": "b" * 64, "retrieved_at": "2026-11-06T12:00:00Z"}],
        assessed_at="2026-11-06T12:05:00Z",
    )
    assert reassessed["material_change"] is True
    assert reassessed["comparison"]["comparison_mode"] == "evidence_changes_only"
    assert reassessed["comparison"]["inventory_changed"] is False
    assert reassessed["comparison"]["newly_observed_cves"] == ["CVE-2026-55555"]
    assert reassessed["dataset"]["meta"]["inventory_scanned_at"] == "2026-11-01T00:00:00Z"

    # Finding 4A: Complete refreshed result with 0 CVE findings and 1 clean evaluated package clears obsolete CVE
    for clean_result_payload in (
        {
            "evaluated_library_ids": ["maven|org.springframework|spring-web|5.3.20"],
            "cve_findings": [],
            "clean_exact_package_versions": 1,
        },
        {
            "cve_findings": [],
            "clean_exact_package_versions": 1,
        },
    ):
        cleared = reassess_inventory_with_refreshed_evidence(
            collection_id="finos-labs",
            baseline_dataset=base_ds,
            baseline_receipt=base_rec,
            refreshed_osv_collection_result=clean_result_payload,
            refreshed_evidence_snapshot_ids={"osv": "osv-3", "kev": "kev-2"},
            refreshed_sources=[{"name": "osv", "sha256": "c" * 64, "retrieved_at": "2026-11-07T12:00:00Z"}],
            assessed_at="2026-11-07T12:05:00Z",
        )
        assert cleared["material_change"] is True
        assert cleared["dataset"]["libraries"] == []
        assert cleared["dataset"]["meta"]["counts"]["distinct_cve_libraries"] == 0
        assert cleared["dataset"]["meta"]["counts"]["unique_cves"] == 0
        assert cleared["dataset"]["consumer_projects"][0]["vulnerable_library_ids"] == []
        assert cleared["dataset"]["consumer_projects"][0]["vulnerable_library_count"] == 0
        assert cleared["comparison"]["resolved_cves"] == ["CVE-2024-22243"]
        assert cleared["comparison"]["resolved_libraries"] == ["maven|org.springframework|spring-web|5.3.20"]

    # Finding 4B: Partial CVE withdrawal + new CVE addition on the same library reconciles both
    partial_withdrawn = reassess_inventory_with_refreshed_evidence(
        collection_id="finos-labs",
        baseline_dataset=reassessed["dataset"],
        baseline_receipt=reassessed["receipt"],
        refreshed_osv_collection_result={
            "evaluated_library_ids": ["maven|org.springframework|spring-web|5.3.20"],
            "cve_findings": [
                {
                    "library_id": "maven|org.springframework|spring-web|5.3.20",
                    "cve_aliases": ["CVE-2026-55555", "CVE-2026-88888"],
                    "summary": "CVE-2024-22243 withdrawn; CVE-2026-88888 added",
                }
            ],
        },
        refreshed_evidence_snapshot_ids={"osv": "osv-4", "kev": "kev-2"},
        refreshed_sources=[{"name": "osv", "sha256": "d" * 64, "retrieved_at": "2026-11-08T12:00:00Z"}],
        assessed_at="2026-11-08T12:05:00Z",
    )
    assert [c["cve_id"] for c in partial_withdrawn["dataset"]["libraries"][0]["cves"]] == [
        "CVE-2026-55555",
        "CVE-2026-88888",
    ]
    assert partial_withdrawn["comparison"]["resolved_cves"] == ["CVE-2024-22243"]
    assert partial_withdrawn["comparison"]["newly_observed_cves"] == ["CVE-2026-88888"]

    # Finding 4C: Explicit unknown/incomplete states are preserved untouched when not cleanly assessed
    ds_with_incomplete = copy.deepcopy(base_ds)
    ds_with_incomplete["libraries"].append(
        {
            "id": "npm||lodash|^4.17.0",
            "namespace": "npm",
            "meta": "",
            "proj": "lodash",
            "release": "^4.17.0",
            "assessment_status": "unknown_unresolved_range",
            "cves": [],
        }
    )
    rec_with_incomplete = build_assessment_receipt(
        collection_id="finos-labs",
        dataset=ds_with_incomplete,
        inventory_snapshot_id="finos-labs-inv-inc",
        evidence_snapshot_ids={"osv": "osv-1", "kev": "kev-1"},
        sources=[{"name": "osv", "sha256": "e" * 64, "retrieved_at": "2026-11-01T00:05:00Z"}],
        artifacts=[{"role": "dataset", "path": "data/finos-labs.json"}],
        collector_commit="07ee91e7e264a530b7be987e40477fbb48d613af",
        generated_at="2026-11-01T00:10:00Z",
    )
    preserved_inc = reassess_inventory_with_refreshed_evidence(
        collection_id="finos-labs",
        baseline_dataset=ds_with_incomplete,
        baseline_receipt=rec_with_incomplete,
        refreshed_osv_collection_result={
            "evaluated_library_ids": ["maven|org.springframework|spring-web|5.3.20"],
            "cve_findings": [],
            "clean_exact_package_versions": 1,
            "unresolved_range_edges": [{"ecosystem": "npm", "package": "lodash", "version": "^4.17.0"}],
        },
        refreshed_evidence_snapshot_ids={"osv": "osv-5", "kev": "kev-2"},
        refreshed_sources=[{"name": "osv", "sha256": "f" * 64, "retrieved_at": "2026-11-09T12:00:00Z"}],
        assessed_at="2026-11-09T12:05:00Z",
    )
    remaining_ids = [lib["id"] for lib in preserved_inc["dataset"]["libraries"]]
    assert remaining_ids == ["npm||lodash|^4.17.0"]
    assert preserved_inc["dataset"]["libraries"][0]["assessment_status"] == "unknown_unresolved_range"
    assert preserved_inc["dataset"]["meta"]["counts"]["distinct_cve_libraries"] == 0

    # Offline replay verification
    replay_check = verify_offline_replay_determinism(
        dataset=reassessed["dataset"],
        receipt=reassessed["receipt"],
    )
    assert replay_check["verified"] is True
    assert replay_check["comparison_mode"] == "no_semantic_change"

    # Deployment manifest & stale candidate promotion guard (#73 ADR 2026-11-09)
    dep_m1 = build_deployment_manifest(
        deployed_code_sha="07ee91e7e264a530b7be987e40477fbb48d613af",
        collection_receipts=[base_rec],
        evidence_snapshot_ids={"osv": "osv-1", "kev": "kev-1"},
        producing_run_id="1001",
        generated_at="2026-11-05T12:00:00Z",
        previous_deployment_sequence=10,
    )
    assert dep_m1["deployment_sequence"] == 11
    assert verify_promotion_candidate_not_stale(None, dep_m1)["promotable"] is True

    dep_m2 = build_deployment_manifest(
        deployed_code_sha="07ee91e7e264a530b7be987e40477fbb48d613af",
        collection_receipts=[reassessed["receipt"]],
        evidence_snapshot_ids={"osv": "osv-2", "kev": "kev-2"},
        producing_run_id="1002",
        generated_at="2026-11-06T12:05:00Z",
        previous_deployment_sequence=11,
    )
    assert verify_promotion_candidate_not_stale(dep_m1, dep_m2)["promotable"] is True
    # Older candidate cannot overwrite newer deployed manifest
    assert verify_promotion_candidate_not_stale(dep_m2, dep_m1)["promotable"] is False

    # CLI entry point verification against complete-provenance fixture tree
    assert (
        cli_main(
            [
                "--validate-status",
                "--root-dir",
                str(FIXTURE_PIPELINE_ROOT),
                "--status-path",
                str(FIXTURE_PIPELINE_STATUS_PATH),
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "--verify-replay",
                str(FIXTURE_PIPELINE_ROOT / "data" / "finos-github-org.json"),
                "--receipt",
                str(FIXTURE_PIPELINE_ROOT / "data" / "receipts" / "finos-github-org.receipt.json"),
            ]
        )
        == 0
    )


class IncrementalRefreshPipelineTestCase(unittest.TestCase):
    def test_all(self):
        test_collections_config_and_incremental_inventory_reuse_readme_change_and_shrink_guard()
        test_cross_collection_osv_deduplication_pagination_negative_cache_expiry_and_non_cve_preservation()
        test_omitted_timestamps_use_current_clock_and_expire_positive_and_negative_osv_cache()
        test_canonical_hash_receipt_comparison_modes_and_safe_publication_rollback()
        test_pipeline_status_updates_stale_running_reconciliation_and_secret_redaction()
        test_public_pipeline_status_provenance_same_date_uniqueness_and_historical_honesty()
        test_conditional_shared_evidence_refresh_evidence_only_reassessment_and_offline_replay_cli()


if __name__ == "__main__":
    unittest.main()

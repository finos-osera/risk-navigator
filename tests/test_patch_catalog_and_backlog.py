import copy
import json
import unittest
from pathlib import Path

from patch_feeds import (
    compare_patch_options,
    ingest_osera_backlog_snapshot,
    load_patch_feeds,
    normalize_common_catalog_entry,
    parse_catalog_csv,
    parse_supported_lines_csv,
    reconcile_backlog_with_estate,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT_DIR / "data" / "fixtures" / "patch-catalog-backlog"
COMMON_CATALOG_JSON_PATH = FIXTURE_DIR / "common-catalog-upstream-osera-commercial.json"
COMMON_CATALOG_CSV_PATH = FIXTURE_DIR / "common-catalog-commercial.csv"
MEMBER_OVERLAY_JSON_PATH = FIXTURE_DIR / "member-catalog-overlay.json"
OSERA_BACKLOG_SNAPSHOT_PATH = FIXTURE_DIR / "osera-backlog-tomcat-snapshot.json"

EVAL_TIME = "2026-10-28T00:00:00Z"


def test_common_catalog_represents_upstream_osera_and_commercial_with_provenance():
    catalog_doc = json.loads(COMMON_CATALOG_JSON_PATH.read_text(encoding="utf-8"))
    overlay_doc = json.loads(MEMBER_OVERLAY_JSON_PATH.read_text(encoding="utf-8"))

    component = {
        "purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "advisories": ["GHSA-22243-spring", "CVE-2024-22259", "CVE-2024-22262"],
    }
    result = compare_patch_options(
        component,
        [catalog_doc],
        member_overlay=overlay_doc,
        evaluation_time=EVAL_TIME,
    )

    assert result["providers_represented"] == ["commercial", "osera", "upstream"]
    ready_by_kind = {opt["provider_kind"]: opt for opt in result["ready_options"]}
    assert set(ready_by_kind.keys()) == {"upstream", "osera", "commercial"}

    # OSERA option fixes all 3 advisories (including GHSA alias normalization) with 0 remaining
    osera_opt = ready_by_kind["osera"]
    assert osera_opt["source_version"] == "5.3.20"
    assert osera_opt["exact_target"] == "pkg:maven/org.springframework/spring-web@5.3.20-osera-00002"
    assert osera_opt["evidence_freshness"] == "2026-10-26T09:30:00Z"
    assert osera_opt["remaining_vulnerabilities"] == []
    assert osera_opt["internal_repository_url"] == "https://nexus.internal.bank.example/repository/finos-osera-releases/"

    # Upstream option exposes residual_advisories and remaining CVE-2024-22262
    upstream_opt = ready_by_kind["upstream"]
    assert upstream_opt["exact_target"] == "pkg:maven/org.springframework/spring-web@5.3.39"
    assert "CVE-2024-22262" in upstream_opt["remaining_vulnerabilities"]
    assert "CVE-2016-1000027" in upstream_opt["remaining_vulnerabilities"]

    # Commercial option carries explicit vendor_version_mapping, fix_evidence, and overlay entitlement/pricing
    comm_opt = ready_by_kind["commercial"]
    assert comm_opt["provider"] == "RedHat"
    assert comm_opt["exact_target"] == "pkg:maven/org.springframework/spring-web@5.3.20.redhat-00004"
    assert comm_opt["entitlement_status"] == "entitled"
    assert comm_opt["pricing"]["contract_id"] == "ENT-RH-2026-009"
    assert comm_opt["vendor_version_mapping"]["upstream_equivalent_version"] == "5.3.34"


def test_coverage_without_release_future_availability_expired_entitlement_and_withdrawn_cannot_be_ready():
    catalog_doc = json.loads(COMMON_CATALOG_JSON_PATH.read_text(encoding="utf-8"))
    overlay_doc = json.loads(MEMBER_OVERLAY_JSON_PATH.read_text(encoding="utf-8"))

    component = {
        "purl": "pkg:maven/org.springframework/spring-web@5.3.20",
        "advisories": ["CVE-2024-22243"],
    }
    result = compare_patch_options(
        component,
        [catalog_doc],
        member_overlay=overlay_doc,
        evaluation_time=EVAL_TIME,
    )
    by_id = {opt["patch_id"]: opt for opt in result["options"]}

    # 1. Coverage commitment without release
    cov_only = by_id["osera-coverage-commitment-without-release"]
    assert cov_only["ready"] is False
    assert "coverage_commitment_without_release" in cov_only["blocked_reasons"]

    # 2. Future delayed availability
    future_opt = by_id["osera-future-delayed-availability"]
    assert future_opt["ready"] is False
    assert "future_delayed_availability" in future_opt["blocked_reasons"]

    # 3. Expired entitlement in member overlay
    expired_opt = by_id["commercial-expired-entitlement-herodevs"]
    assert expired_opt["ready"] is False
    assert expired_opt["entitlement_status"] == "expired"
    assert "expired_entitlement" in expired_opt["blocked_reasons"]

    # 4. Withdrawn artifact
    withdrawn_opt = by_id["osera-withdrawn-artifact-00001"]
    assert withdrawn_opt["ready"] is False
    assert "withdrawn_artifact" in withdrawn_opt["blocked_reasons"]

    # 5. No entitlement, price, or commercial coverage inferred from existence of a fork or marketing
    unentitled_opt = by_id["commercial-unentitled-fork-vendor"]
    assert unentitled_opt["ready"] is False
    assert unentitled_opt["entitlement_status"] == "unentitled"
    assert unentitled_opt["pricing"] is None
    assert "missing_commercial_entitlement" in unentitled_opt["blocked_reasons"]

    # 6. Commercial backport missing vendor-version mapping / fix evidence is blocked
    unmapped_opt = by_id["commercial-missing-vendor-mapping"]
    assert unmapped_opt["ready"] is False
    assert "missing_commercial_vendor_mapping_or_fix_evidence" in unmapped_opt["blocked_reasons"]


def test_csv_catalog_import_and_provider_artifact_separation():
    csv_catalog = parse_catalog_csv(
        COMMON_CATALOG_CSV_PATH,
        {"feed_id": "csv-imported-feed", "provider": "MultiCSV", "as_of": "2026-10-27T18:00:00Z"},
    )
    assert csv_catalog["schema_version"] == "osera-patch-catalog/v1"
    assert len(csv_catalog["patches"]) == 2

    loaded = load_patch_feeds([{"config": {"adapter": "catalog_csv", "feed_id": "csv-imported-feed"}, "csv": COMMON_CATALOG_CSV_PATH}])
    assert loaded["feeds"][0]["patch_count"] == 2
    loaded_purls = {p["replacement_purl"] for p in loaded["patches"]}
    assert "pkg:maven/org.springframework/spring-web@5.3.20.redhat-00004" in loaded_purls
    assert "pkg:maven/org.springframework/spring-web@5.3.20-osera-00002" in loaded_purls


def test_osera_backlog_distinguishes_deployed_tomcat_from_latest_patch_and_preserves_states():
    ingested = ingest_osera_backlog_snapshot(OSERA_BACKLOG_SNAPSHOT_PATH)
    assert ingested["schema_version"] == "osera-backlog-snapshot/v1"
    assert ingested["read_only"] is True
    assert ingested["metadata"]["source_commit"] == "9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
    assert ingested["metadata"]["book_version"] == "2026.10.27"
    assert ingested["metadata"]["snapshot_consistent"] is True

    # Canonical advisory deduplication: CVE-2024-24549 and GHSA-tomcat-24549 collapse into 1 canonical backlog item
    tomcat_items = [i for i in ingested["backlog_items"] if i["library"] == "org.apache.tomcat.embed:tomcat-embed-core"]
    statuses = {i["advisory_id"]: i["status"] for i in tomcat_items}
    assert statuses["CVE-2024-24549"] == "fixed"
    assert statuses["CVE-2024-23672"] == "in_progress"
    assert statuses["CVE-2024-50379"] == "open"
    assert statuses["CVE-2022-99999"] == "not_remediable"
    assert statuses["CVE-2023-46589"] == "excluded"

    # Reconcile against member estate with old deployed Tomcat 9.0.50
    estate_obs = [
        {
            "application_id": "payments-gateway",
            "purl": "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.50",
            "cves": [
                "CVE-2024-24549",
                "CVE-2024-23672",
                "CVE-2024-50379",
                "CVE-2022-99999",
                "CVE-2023-46589",
            ],
        }
    ]
    reconciled = reconcile_backlog_with_estate(ingested, estate_obs)
    row = reconciled["rows"][0]

    assert row["deployed_version"] == "9.0.50"
    assert row["pinned_baseline"] == "9.0.70"
    assert row["latest_patch_resolution"] == "9.0.85-osera-00001"
    assert row["member_deployment_state"] == "deployed_vulnerable_fix_available"
    assert row["deployed_findings_cleared_by_reference_graph"] is False
    assert len(row["active_deployed_findings"]) == 5
    assert [f["advisory_id"] for f in row["available_fixes"]] == ["CVE-2024-24549"]
    assert row["excluded_findings"][0]["advisory_id"] == "CVE-2023-46589"
    assert row["excluded_findings"][0]["remediated_in_estate"] is False


def test_partial_line_coverage_empty_consume_coordinate_companion_boms_and_data_quality_issues():
    ingested = ingest_osera_backlog_snapshot(OSERA_BACKLOG_SNAPSHOT_PATH)
    lines_by_id = {ln["line_id"]: ln for ln in ingested["supported_lines"]}

    # Tomcat 9.0.x has partial coverage: 1 available fix + remaining open/in_progress/not_remediable items
    tomcat_line = lines_by_id["tomcat-embed-core:9.0.x"]
    assert tomcat_line["coverage_state"] == "partial_coverage"
    assert len(tomcat_line["available_fixes"]) == 1
    assert tomcat_line["available_fixes"][0]["advisory_id"] == "CVE-2024-24549"

    # Companion BOM, parent, plugin, and companion artifacts are modeled without inflating unique vulnerability fix count
    assert tomcat_line["unique_vulnerability_fix_count"] == 1
    assert tomcat_line["companion_artifact_count"] == 4
    bom_roles = {m["role"] for m in tomcat_line["consumption_bom_details"]["members"]}
    assert bom_roles == {"primary", "bom", "parent", "plugin", "companion"}

    # Netty 4.1.x has an empty consume coordinate, so availability is NOT granted even when fixed_by is present
    netty_line = lines_by_id["netty-handler:4.1.x"]
    assert netty_line["consume_coordinate"] == ""
    assert netty_line["available_fixes"] == []

    # Actionable data-quality issues surfaced for unexpected artifacts, missing fixed_by, empty consume, and inconsistent snapshots
    issue_kinds = {d["kind"] for d in ingested["data_quality_issues"]}
    assert "unexpected_artifact_version" in issue_kinds
    assert "missing_fixed_by_on_fixed_item" in issue_kinds
    assert "empty_consume_coordinate" in issue_kinds
    assert "fixed_item_empty_consume_coordinate" in issue_kinds

    # Inconsistent commit across snapshot files surfaces inconsistent_snapshot error
    inconsistent_raw = json.loads(OSERA_BACKLOG_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    inconsistent_raw["metadata"]["component_commits"]["pinned-graph.json"] = "0000000000000000000000000000000000000000"
    inconsistent_ingested = ingest_osera_backlog_snapshot(inconsistent_raw)
    assert inconsistent_ingested["metadata"]["snapshot_consistent"] is False
    assert any(d["kind"] == "inconsistent_snapshot" for d in inconsistent_ingested["data_quality_issues"])


class PatchCatalogAndBacklogTestCase(unittest.TestCase):
    def test_all(self):
        test_common_catalog_represents_upstream_osera_and_commercial_with_provenance()
        test_coverage_without_release_future_availability_expired_entitlement_and_withdrawn_cannot_be_ready()
        test_csv_catalog_import_and_provider_artifact_separation()
        test_osera_backlog_distinguishes_deployed_tomcat_from_latest_patch_and_preserves_states()
        test_partial_line_coverage_empty_consume_coordinate_companion_boms_and_data_quality_issues()


if __name__ == "__main__":
    unittest.main()

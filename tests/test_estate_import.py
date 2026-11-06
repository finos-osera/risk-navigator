from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_dataset import build_dataset  # noqa: E402
from estate_import import (  # noqa: E402
    COMPANY_OVERLAY_SCHEMA_VERSION,
    ESTATE_CONTRACT_SCHEMA_VERSION,
    SCOPE_DATASET_SCHEMA_VERSION,
    apply_company_overlay,
    generate_remediation_recipes,
    import_estate_sources,
    parse_purl_rich,
    sanitize_for_public_export,
)
from extract_org import extract_from_estate  # noqa: E402
from validate_dataset import validate as validate_dataset_schema  # noqa: E402

FIXTURES_DIR = ROOT / "data" / "fixtures" / "estate-import"


def _fixture_paths() -> list[Path]:
    return [
        FIXTURES_DIR / "cyclonedx-build-101-prod-us.json",
        FIXTURES_DIR / "cyclonedx-build-102-prod-eu.json",
        FIXTURES_DIR / "spdx-settlement-worker.spdx.json",
        FIXTURES_DIR / "cyclonedx-graphless-legacy.json",
        FIXTURES_DIR / "company-inventory-feed.json",
    ]


def _write_test_vuln_db(path: Path) -> Path:
    vuln_db = {
        "maven|org.springframework|spring-web": {
            "releases": [
                {
                    "release": "5.3.20",
                    "release_date": "2022-05-11",
                    "cves": [
                        {
                            "cve_id": "CVE-2024-22243",
                            "cvss": 8.1,
                            "priority": "P1",
                            "exploitability": "HIGH",
                            "summary": "Spring Web UriComponentsBuilder open redirect and SSRF",
                            "fixed_in": "5.3.32",
                        }
                    ],
                },
                {
                    "release": "5.3.32",
                    "release_date": "2024-02-22",
                    "cves": [],
                },
                {
                    "release": "6.1.4",
                    "release_date": "2024-02-22",
                    "cves": [],
                },
            ]
        },
        "maven|com.fasterxml.jackson.core|jackson-databind": {
            "releases": [
                {
                    "release": "2.13.3",
                    "release_date": "2022-05-14",
                    "cves": [
                        {
                            "cve_id": "CVE-2022-42003",
                            "cvss": 7.5,
                            "priority": "P2",
                            "exploitability": "MATURE",
                            "summary": "Jackson Databind deep wrapper array nesting resource exhaustion",
                            "fixed_in": "2.13.4.2",
                        }
                    ],
                },
                {
                    "release": "2.13.3-acme-internal-1",
                    "release_date": "2023-01-10",
                    "cves": [
                        {
                            "cve_id": "CVE-2022-42004",
                            "cvss": 7.5,
                            "priority": "P2",
                            "exploitability": "MATURE",
                            "summary": "Jackson Databind nested array deserialization stack overflow",
                            "fixed_in": "2.15.0",
                        }
                    ],
                },
                {
                    "release": "2.15.0",
                    "release_date": "2023-04-23",
                    "cves": [],
                },
            ]
        },
        "maven|org.apache.logging.log4j|log4j-core": {
            "releases": [
                {
                    "release": "2.14.1",
                    "release_date": "2021-03-06",
                    "cves": [
                        {
                            "cve_id": "CVE-2021-44228",
                            "cvss": 10.0,
                            "priority": "P1",
                            "exploitability": "HIGH",
                            "summary": "Apache Log4j2 JNDI remote code execution",
                            "fixed_in": "2.17.1",
                        }
                    ],
                },
                {
                    "release": "2.17.1",
                    "release_date": "2021-12-27",
                    "cves": [],
                },
            ]
        },
        "maven|org.yaml|snakeyaml": {
            "releases": [
                {
                    "release": "1.30",
                    "release_date": "2021-12-14",
                    "cves": [
                        {
                            "cve_id": "CVE-2022-1471",
                            "cvss": 8.3,
                            "priority": "P1",
                            "exploitability": "HIGH",
                            "summary": "SnakeYAML Constructor arbitrary code execution",
                            "fixed_in": "2.0",
                        }
                    ],
                },
                {
                    "release": "2.0",
                    "release_date": "2023-02-26",
                    "cves": [],
                },
            ]
        },
        "rpm|redhat|openssl-libs": {
            "releases": [
                {
                    "release": "3.0.7-24.el9",
                    "release_date": "2023-11-14",
                    "cves": [
                        {
                            "cve_id": "CVE-2023-5678",
                            "cvss": 7.5,
                            "priority": "P2",
                            "exploitability": "PROOF_OF_CONCEPT",
                            "summary": "OpenSSL DH key generation excessive time",
                            "fixed_in": "3.0.7-27.el9",
                        }
                    ],
                },
                {
                    "release": "3.0.7-27.el9",
                    "release_date": "2024-02-01",
                    "cves": [],
                },
            ]
        },
        "generic|unknown|libcrypto": {
            "releases": [
                {
                    "release": "1.1.1k",
                    "release_date": "2021-03-25",
                    "cves": [
                        {
                            "cve_id": "CVE-2021-3711",
                            "cvss": 9.8,
                            "priority": "P1",
                            "exploitability": "HIGH",
                            "summary": "SM2 decryption buffer overflow",
                            "fixed_in": "1.1.1l",
                        }
                    ],
                }
            ]
        },
    }
    path.write_text(json.dumps(vuln_db, indent=2), encoding="utf-8")
    return path


def test_estate_contract_separates_app_build_and_deployment_identities() -> None:
    contract = import_estate_sources(_fixture_paths(), scope="acme-estate")

    assert contract["schema_version"] == ESTATE_CONTRACT_SCHEMA_VERSION
    assert contract["compatibility"]["scope_dataset_schema"] == SCOPE_DATASET_SCHEMA_VERSION

    # 4 distinct canonical applications across 5 input documents:
    # payments-engine (imported 3 times across 2 builds and 3 deployments),
    # settlement-worker, legacy-batch-ledger, treasury-portal.
    apps_by_id = {app["id"]: app for app in contract["applications"]}
    assert set(apps_by_id.keys()) == {
        "github|acme|payments-engine|main",
        "github|acme|settlement-worker|main",
        "github|acme|legacy-batch-ledger|main",
        "github|acme|treasury-portal|main",
    }

    payments_app = apps_by_id["github|acme|payments-engine|main"]
    assert payments_app["build_count"] == 2
    assert set(payments_app["builds"]) == {"build-101", "build-102"}
    assert payments_app["deployment_count"] == 3
    assert set(payments_app["deployments"]) == {
        "deploy-prod-us-east",
        "deploy-prod-eu-west",
        "deploy-dr-us-central",
    }
    assert set(payments_app["environments"]) == {"production", "dr"}

    # Distinct deployments remain traceable with region/cluster/build metadata
    deployments_by_id = {d["deployment_id"]: d for d in contract["deployments"]}
    assert deployments_by_id["deploy-prod-us-east"]["build_id"] == "build-101"
    assert deployments_by_id["deploy-prod-eu-west"]["build_id"] == "build-102"
    assert deployments_by_id["deploy-dr-us-central"]["environment"] == "dr"


def test_preserves_purls_qualifiers_subpaths_digests_paths_scopes_and_timestamps() -> None:
    parsed = parse_purl_rich(
        "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rhel-9.3#crypto/fips"
    )
    assert parsed is not None
    assert parsed["namespace"] == "rpm"
    assert parsed["meta"] == "redhat"
    assert parsed["proj"] == "openssl-libs"
    assert parsed["release"] == "3.0.7-24.el9"
    assert parsed["qualifiers"] == {"arch": "x86_64", "distro": "rhel-9.3"}
    assert parsed["subpath"] == "crypto/fips"

    contract = import_estate_sources(_fixture_paths(), scope="acme-estate")
    comps_by_id = {c["library_id"]: c for c in contract["components"]}

    # Qualifier preservation on RPM package
    openssl = comps_by_id["rpm|redhat|openssl-libs|3.0.7-24.el9"]
    assert openssl["qualifiers"] == {"arch": ["x86_64"], "distro": ["rhel-9.3"]}
    assert openssl["identity_status"] == "qualified_or_repackaged"
    assert any("distro=rhel-9.3" in r for r in openssl["uncertain_match_reasons"])
    assert openssl["digests"] == [
        {
            "algorithm": "SHA-256",
            "value": "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f",
        }
    ]

    # Internally repackaged library survival & visibility
    repackaged = comps_by_id["maven|com.fasterxml.jackson.core|jackson-databind|2.13.3-acme-internal-1"]
    assert repackaged["is_repackaged"] is True
    assert repackaged["identity_status"] == "qualified_or_repackaged"
    assert repackaged["qualifiers"]["classifier"] == ["shaded"]
    assert repackaged["qualifiers"]["repository_url"] == ["https://nexus.corp.acme.internal/maven-releases"]
    assert any("internally repackaged" in r for r in repackaged["uncertain_match_reasons"])

    # Ambiguous identity visibility
    ambiguous = comps_by_id["generic|unknown|libcrypto|1.1.1k"]
    assert ambiguous["identity_status"] == "ambiguous"
    assert any("generic ecosystem" in r or "missing vendor/group" in r for r in ambiguous["uncertain_match_reasons"])

    # Subpath preservation on Go package from SPDX
    gin = comps_by_id["golang|github.com/gin-gonic|gin|1.9.0"]
    assert gin["subpaths"] == ["binding/json"]
    assert "pkg:golang/github.com/gin-gonic/gin@v1.9.0#binding/json" in gin["observed_purls"]

    # Transitive dependency paths & shared component across payments-engine and settlement-worker
    jackson = comps_by_id["maven|com.fasterxml.jackson.core|jackson-databind|2.13.3"]
    assert jackson["total_consumer_count"] == 2
    assert jackson["direct_consumer_count"] == 0
    assert jackson["transitive_consumer_count"] == 2
    assert jackson["dependency_classification"] == "transitive"
    assert jackson["scopes"] == ["required"]
    assert jackson["observed_at"] == "2026-10-24T12:00:00Z"
    assert [
        "github|acme|payments-engine|main",
        "maven|org.springframework|spring-web|5.3.20",
        "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3",
    ] in jackson["dependency_paths"]
    assert [
        "github|acme|settlement-worker|main",
        "maven|org.springframework|spring-web|5.3.20",
        "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3",
    ] in jackson["dependency_paths"]


def test_missing_graphs_produce_unknown_classification_and_suppress_direct_recipes(tmp_path: Path) -> None:
    vuln_db_path = _write_test_vuln_db(tmp_path / "vuln_db.json")
    raw_root = tmp_path / "raw"
    out_dir = tmp_path / "out"
    ext_dir = tmp_path / "external"
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "kev.json").write_text(json.dumps({"fetched_at": "2026-10-24T00:00:00Z", "cve_ids": ["CVE-2021-44228"]}), encoding="utf-8")
    (ext_dir / "epss.json").write_text(json.dumps({"fetched_at": "2026-10-24T00:00:00Z", "scores": {"CVE-2021-44228": 0.975}}), encoding="utf-8")

    extract_from_estate(
        scope="acme-estate",
        raw_root=raw_root,
        estate_paths=_fixture_paths(),
        vuln_db_path=vuln_db_path,
    )

    dataset = build_dataset(
        scope="acme-estate",
        raw_root=raw_root,
        external_dir=ext_dir,
        output_dir=out_dir,
        vuln_db=vuln_db_path,
        enrich_release_dates=False,
        enrich_cve_metadata_online=False,
    )
    assert validate_dataset_schema(out_dir / "acme-estate.json") == []
    assert dataset["meta"]["schema_version"] == SCOPE_DATASET_SCHEMA_VERSION

    libs_by_id = {lib["id"]: lib for lib in dataset["libraries"]}

    # Graphless SBOM component: log4j-core@2.14.1 in legacy-batch-ledger
    log4j = libs_by_id["maven|org.apache.logging.log4j|log4j-core|2.14.1"]
    assert log4j["dependency_classification"] == "unknown"
    assert log4j["direct_consumer_count"] == 0
    assert log4j["transitive_consumer_count"] == 0
    assert log4j["unknown_consumer_count"] == 1
    assert log4j["unknown_consumer_project_ids"] == ["github|acme|legacy-batch-ledger|main"]

    # Graphless component across 2 graphless apps (legacy-batch-ledger + treasury-portal): snakeyaml@1.30
    snakeyaml = libs_by_id["maven|org.yaml|snakeyaml|1.30"]
    assert snakeyaml["dependency_classification"] == "unknown"
    assert snakeyaml["direct_consumer_count"] == 0
    assert snakeyaml["transitive_consumer_count"] == 0
    assert snakeyaml["unknown_consumer_count"] == 2

    # Repeated SBOM imports across builds/deployments did not inflate exposure counts on spring-web
    spring_web = libs_by_id["maven|org.springframework|spring-web|5.3.20"]
    assert spring_web["dependency_classification"] == "direct"
    assert spring_web["total_consumer_count"] == 2
    assert spring_web["direct_consumer_count"] == 2
    assert spring_web["transitive_consumer_count"] == 0
    assert spring_web["unknown_consumer_count"] == 0

    # Remediation recipe generation suppresses unknown (graphless) and transitive-only libraries
    recipes = generate_remediation_recipes(dataset["libraries"], scope_name="acme-estate")
    recipe_lib_ids = {r["library_id"] for r in recipes["recipes"]}
    assert "maven|org.springframework|spring-web|5.3.20" in recipe_lib_ids
    assert "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3-acme-internal-1" in recipe_lib_ids
    assert "maven|org.apache.logging.log4j|log4j-core|2.14.1" not in recipe_lib_ids
    assert "maven|org.yaml|snakeyaml|1.30" not in recipe_lib_ids
    assert "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3" not in recipe_lib_ids

    suppressed_by_id = {s["library_id"]: s for s in recipes["suppressed"]}
    assert suppressed_by_id["maven|org.apache.logging.log4j|log4j-core|2.14.1"]["reason"] == "dependency_classification_unknown_missing_graph"
    assert suppressed_by_id["maven|org.yaml|snakeyaml|1.30"]["reason"] == "dependency_classification_unknown_missing_graph"
    assert suppressed_by_id["maven|com.fasterxml.jackson.core|jackson-databind|2.13.3"]["reason"] == "no_direct_consumers_transitive_only"

    # Completeness and unmapped records are reported
    estate_meta = dataset["meta"]["estate_import"]
    assert estate_meta["schema_version"] == ESTATE_CONTRACT_SCHEMA_VERSION
    assert estate_meta["unmapped_records_count"] == 2
    assert len(dataset["unmapped_records"]) == 2
    completeness = estate_meta["completeness"]
    assert completeness["applications_with_dependency_graph"] == 2
    assert completeness["applications_without_dependency_graph"] == 2
    assert completeness["unmapped_records"] == 2


def test_company_overlay_modifies_filtering_and_prioritization_without_disclosing_private_inventory(tmp_path: Path) -> None:
    vuln_db_path = _write_test_vuln_db(tmp_path / "vuln_db.json")
    raw_root = tmp_path / "raw"
    out_dir = tmp_path / "out"
    ext_dir = tmp_path / "external"
    ext_dir.mkdir(parents=True, exist_ok=True)
    (ext_dir / "kev.json").write_text(json.dumps({"fetched_at": "2026-10-24T00:00:00Z", "cve_ids": []}), encoding="utf-8")
    (ext_dir / "epss.json").write_text(json.dumps({"fetched_at": "2026-10-24T00:00:00Z", "scores": {}}), encoding="utf-8")

    extract_from_estate(
        scope="acme-estate",
        raw_root=raw_root,
        estate_paths=_fixture_paths(),
        vuln_db_path=vuln_db_path,
    )

    base_dataset = build_dataset(
        scope="acme-estate",
        raw_root=raw_root,
        external_dir=ext_dir,
        output_dir=out_dir,
        vuln_db=vuln_db_path,
        enrich_release_dates=False,
        enrich_cve_metadata_online=False,
    )

    overlay = json.loads((FIXTURES_DIR / "company-overlay-sample.json").read_text(encoding="utf-8"))
    assert overlay["schema_version"] == COMPANY_OVERLAY_SCHEMA_VERSION

    overlaid = apply_company_overlay(base_dataset, overlay)

    # Verify prioritization changed:
    # payments-engine is tier_0 + external + production (multiplier 1.5 * 1.35 * 1.25 = 2.5312),
    # while legacy-batch-ledger is low + isolated + production (multiplier 0.75 * 0.8 * 1.25 = 0.75).
    base_libs = {lib["id"]: lib for lib in base_dataset["libraries"]}
    over_libs = {lib["id"]: lib for lib in overlaid["libraries"]}

    assert over_libs["maven|org.springframework|spring-web|5.3.20"]["risk_signal"] > base_libs["maven|org.springframework|spring-web|5.3.20"]["risk_signal"]
    assert over_libs["maven|org.apache.logging.log4j|log4j-core|2.14.1"]["risk_signal"] < base_libs["maven|org.apache.logging.log4j|log4j-core|2.14.1"]["risk_signal"]

    # Runtime constraint (major_upgrade_blocked=True on payments-engine) escalates MAJOR upgrade
    # on repackaged jackson-databind@2.13.3-acme-internal-1 -> 2.15.0 to CREATE_LIBRARY_FORK
    repackaged_over = over_libs["maven|com.fasterxml.jackson.core|jackson-databind|2.13.3-acme-internal-1"]
    assert repackaged_over["overlay_priority"]["runtime_constrained"] is True
    assert repackaged_over["overlay_recommended_action"] == "CREATE_LIBRARY_FORK"

    # Verify overlay filtering (e.g. environment=["staging"] keeps only settlement-worker)
    filtered_overlay = {
        **overlay,
        "filters": {
            "environments": ["staging"],
        },
    }
    filtered_ds = apply_company_overlay(base_dataset, filtered_overlay)
    assert [p["id"] for p in filtered_ds["consumer_projects"]] == ["github|acme|settlement-worker|main"]

    # Verify public export sanitization strips all private company overlay and internal inventory fields
    sanitized = sanitize_for_public_export(overlaid)
    serialized = json.dumps(sanitized)
    assert "company_overlay" not in serialized
    assert "overlay_priority" not in serialized
    assert "clearing-eng@acme.internal" not in serialized
    assert "CC-9010" not in serialized
    assert "eks-prod-01" not in serialized
    assert "unmapped_records" not in sanitized
    for proj in sanitized["consumer_projects"]:
        assert proj["department"] == "General"
        assert "builds" not in proj
        assert "deployments" not in proj


import tempfile  # noqa: E402
import unittest  # noqa: E402


class EstateImportUnitTests(unittest.TestCase):
    def test_identities(self) -> None:
        test_estate_contract_separates_app_build_and_deployment_identities()

    def test_purls_qualifiers_and_paths(self) -> None:
        test_preserves_purls_qualifiers_subpaths_digests_paths_scopes_and_timestamps()

    def test_unknown_graph_and_recipes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            test_missing_graphs_produce_unknown_classification_and_suppress_direct_recipes(Path(tmp))

    def test_company_overlay_and_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            test_company_overlay_modifies_filtering_and_prioritization_without_disclosing_private_inventory(Path(tmp))


if __name__ == "__main__":
    unittest.main()


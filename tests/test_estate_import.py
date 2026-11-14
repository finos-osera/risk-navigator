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
    APPLICATION_VERSION_ORDERING_POLICY,
    COMPANY_OVERLAY_SCHEMA_VERSION,
    ESTATE_CONTRACT_SCHEMA_VERSION,
    PUBLIC_EXPORT_LIBRARY_ALLOWED_FIELDS,
    PUBLIC_EXPORT_SCHEMA_VERSION,
    SCOPE_DATASET_SCHEMA_VERSION,
    _version_sort_key,
    apply_company_overlay,
    compare_application_versions,
    evaluate_estate_view,
    generate_remediation_recipes,
    import_estate_sources,
    merge_estate_observations,
    parse_company_inventory_feed,
    parse_cyclonedx_document,
    parse_purl_rich,
    parse_spdx_document,
    resolve_application_version_convention,
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

    # Caller's internal dataset must remain intact in memory
    assert len(overlaid["consumer_projects"]) == 4
    assert any(p["id"] == "github|acme|payments-engine|main" for p in overlaid["consumer_projects"])

    # Public export contract schema & top-level exclusions
    assert sanitized["schema_version"] == PUBLIC_EXPORT_SCHEMA_VERSION
    assert sanitized["meta"]["public_export_schema_version"] == PUBLIC_EXPORT_SCHEMA_VERSION
    assert sanitized["consumer_summary"]["total_consumer_projects"] == 4
    assert sanitized["consumer_summary"]["private_inventory_redacted"] is True
    assert "consumer_projects" not in sanitized
    assert "applications" not in sanitized
    assert "application_versions" not in sanitized
    assert "builds" not in sanitized
    assert "deployments" not in sanitized
    assert "unmapped_records" not in sanitized

    # Full serialized payload must not contain any internal application names, repo refs, asset IDs,
    # internal consumer ID lists, internal corporate emails/cost-centers, or internal repo URLs
    forbidden_tokens = [
        "company_overlay",
        "overlay_priority",
        "overlay_evaluation",
        "clearing-eng@acme.internal",
        "CC-9010",
        "eks-prod-01",
        "github|acme|payments-engine|main",
        "github|acme|settlement-worker|main",
        "github|acme|legacy-batch-ledger|main",
        "github|acme|treasury-portal|main",
        "github/acme/payments-engine",
        "github/acme/settlement-worker",
        "payments-engine",
        "settlement-worker",
        "legacy-batch-ledger",
        "treasury-portal",
        "ACME_PAYMENTS_ENGINE",
        "EON-90010",
        "SBOM-1",
        "consumer_project_ids",
        "direct_consumer_project_ids",
        "unknown_consumer_project_ids",
        "consumer_app_ids",
        "nexus.corp.acme.internal",
        "2.13.3-acme-internal-1",
    ]
    for token in forbidden_tokens:
        assert token not in serialized, f"Leaked private token in serialized public export: {token}"

    allowed_lib_keys = set(PUBLIC_EXPORT_LIBRARY_ALLOWED_FIELDS)
    for lib in sanitized["libraries"]:
        assert set(lib.keys()).issubset(allowed_lib_keys)
        assert lib["total_consumer_count"] >= 1
        for dep_path in lib.get("dependency_paths") or []:
            assert dep_path[0] == "<redacted-application>"
            assert all("payments-engine" not in step and "settlement-worker" not in step for step in dep_path)

    # Also verify sanitize_for_public_export on raw estate contract (where dependency_paths are populated)
    raw_contract = import_estate_sources(_fixture_paths(), scope="acme-estate")
    sanitized_contract = sanitize_for_public_export(raw_contract)
    serialized_contract = json.dumps(sanitized_contract)
    for token in forbidden_tokens:
        assert token not in serialized_contract, f"Leaked private token in contract public export: {token}"
    jackson_pub = next(
        lib for lib in sanitized_contract["libraries"]
        if lib["proj"] == "jackson-databind" and not lib["is_repackaged"]
    )
    assert jackson_pub["dependency_paths"] == [
        [
            "<redacted-application>",
            "maven|org.springframework|spring-web|5.3.20",
            "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3",
        ]
    ]
    repackaged_pub = next(
        lib for lib in sanitized_contract["libraries"]
        if lib["proj"] == "jackson-databind" and lib["is_repackaged"]
    )
    assert repackaged_pub["release"] == "2.13.3"
    assert repackaged_pub["repackaged_internal_coordinates_redacted"] is True
    assert "repository_url" not in repackaged_pub["qualifiers"]


def test_two_versions_simultaneously_deployed_in_production_and_view_semantics() -> None:
    """Two versions (1.0.0 and 2.0.0) of the same application simultaneously active in production coexist cleanly."""

    cdx_v1 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:aaaa1111-0000-0000-0000-000000000001",
        "version": 1,
        "metadata": {
            # Imported LATER than v2.0.0 to prove "latest" uses semantic version + active prod, not observed_at
            "timestamp": "2026-10-28T18:00:00Z",
            "properties": [
                {"name": "osera:build_id", "value": "build-v100"},
                {"name": "osera:deployment_id", "value": "deploy-prod-us-v1"},
                {"name": "osera:environment", "value": "production"},
                {"name": "osera:region", "value": "us-east-1"},
                {"name": "osera:deployed_at", "value": "2026-10-15T10:00:00Z"},
            ],
            "component": {
                "type": "application",
                "bom-ref": "app-root",
                "group": "acme",
                "name": "order-router",
                "version": "1.0.0",
                "externalReferences": [{"type": "vcs", "url": "https://github.com/acme/order-router.git"}],
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:maven/org.springframework/spring-web@5.3.20",
                "purl": "pkg:maven/org.springframework/spring-web@5.3.20",
            },
            {
                "type": "library",
                "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            },
        ],
        "dependencies": [
            {
                "ref": "app-root",
                "dependsOn": [
                    "pkg:maven/org.springframework/spring-web@5.3.20",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                ],
            }
        ],
    }

    cdx_v2 = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:aaaa1111-0000-0000-0000-000000000002",
        "version": 1,
        "metadata": {
            "timestamp": "2026-10-22T12:00:00Z",
            "properties": [
                {"name": "osera:build_id", "value": "build-v200"},
                {"name": "osera:deployment_id", "value": "deploy-prod-eu-v2"},
                {"name": "osera:environment", "value": "production"},
                {"name": "osera:region", "value": "eu-west-1"},
                {"name": "osera:deployed_at", "value": "2026-10-22T12:00:00Z"},
            ],
            "component": {
                "type": "application",
                "bom-ref": "app-root",
                "group": "acme",
                "name": "order-router",
                "version": "2.0.0",
                "externalReferences": [{"type": "vcs", "url": "https://github.com/acme/order-router.git"}],
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:maven/org.springframework/spring-web@5.3.20",
                "purl": "pkg:maven/org.springframework/spring-web@5.3.20",
            },
            {
                "type": "library",
                "bom-ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
            },
        ],
        "dependencies": [
            {
                "ref": "app-root",
                "dependsOn": [
                    "pkg:maven/org.springframework/spring-web@5.3.20",
                    "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0",
                ],
            }
        ],
    }

    # Import v2 first and v1 second (so v1 is last in list AND has a newer observed_at timestamp)
    contract = merge_estate_observations([parse_cyclonedx_document(cdx_v2), parse_cyclonedx_document(cdx_v1)])

    assert len(contract["applications"]) == 1
    app = contract["applications"][0]
    assert app["application_id"] == "github|acme|order-router|main"
    assert app["release"] == "2.0.0"
    assert app["latest_version"] == "2.0.0"
    assert app["latest_production_version"] == "2.0.0"
    assert app["active_production_versions"] == ["1.0.0", "2.0.0"]

    av_by_id = {av["application_version_id"]: av for av in app["application_versions"]}
    assert set(av_by_id.keys()) == {
        "github|acme|order-router|main@1.0.0",
        "github|acme|order-router|main@2.0.0",
    }
    assert av_by_id["github|acme|order-router|main@1.0.0"]["active_production"] is True
    assert av_by_id["github|acme|order-router|main@2.0.0"]["active_production"] is True

    # View 1: all_active_production evaluates both 1.0.0 and 2.0.0
    all_prod_view = evaluate_estate_view(contract, "all_active_production")
    assert all_prod_view["evaluated_application_count"] == 1
    assert all_prod_view["evaluated_application_version_count"] == 2
    assert all_prod_view["evaluated_deployment_count"] == 2
    prod_comps = {c["library_id"]: c for c in all_prod_view["components"]}

    # spring-web is in both 1.0.0 and 2.0.0 -> 1 logical app, 2 active app versions, 2 active deployments
    spring = prod_comps["maven|org.springframework|spring-web|5.3.20"]
    assert spring["affected_application_count"] == 1
    assert spring["affected_application_version_count"] == 2
    assert spring["affected_deployment_count"] == 2

    # log4j-core is only in 1.0.0, which is still active in US production -> must remain visible!
    log4j = prod_comps["maven|org.apache.logging.log4j|log4j-core|2.14.1"]
    assert log4j["affected_application_count"] == 1
    assert log4j["affected_application_version_count"] == 1
    assert log4j["consumer_application_version_ids"] == ["github|acme|order-router|main@1.0.0"]

    # View 2: latest_production_version evaluates only 2.0.0
    latest_prod_view = evaluate_estate_view(contract, "latest_production_version")
    assert latest_prod_view["evaluated_application_count"] == 1
    assert latest_prod_view["evaluated_application_version_count"] == 1
    latest_comps = {c["library_id"]: c for c in latest_prod_view["components"]}
    assert "maven|org.apache.logging.log4j|log4j-core|2.14.1" not in latest_comps
    assert latest_comps["maven|org.springframework|spring-web|5.3.20"]["affected_application_version_count"] == 1
    assert latest_comps["maven|com.fasterxml.jackson.core|jackson-databind|2.15.0"]["affected_application_count"] == 1


def test_historical_or_superseded_build_is_excluded_from_active_components() -> None:
    """Obsolete/retired builds and builds superseded on the same deployment_id do not inflate active component counts."""

    active_prod_doc = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-10-20T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-120"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-primary"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-10-20T10:00:00Z"},
                ],
                "component": {"type": "application", "bom-ref": "root", "group": "acme", "name": "ledger-core", "version": "1.2.0"},
            },
            "components": [
                {"type": "library", "bom-ref": "spring", "purl": "pkg:maven/org.springframework/spring-web@5.3.32"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["spring"]}],
        }
    )

    # Historical build 0.9.0 imported with a NEWER observed_at timestamp but status=historical / active=false
    historical_doc = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-10-29T23:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-090-retired"},
                    {"name": "osera:deployment_id", "value": "deploy-archive-090"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:status", "value": "historical"},
                    {"name": "osera:active", "value": "false"},
                ],
                "component": {"type": "application", "bom-ref": "root", "group": "acme", "name": "ledger-core", "version": "0.9.0"},
            },
            "components": [
                {"type": "library", "bom-ref": "cc", "purl": "pkg:maven/commons-collections/commons-collections@3.2.1"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["cc"]}],
        }
    )

    # Older build 1.1.0 that was previously deployed to the SAME deployment_id (deploy-prod-primary) at an earlier deployed_at
    superseded_doc = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-10-10T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-110-old"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-primary"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-10-10T10:00:00Z"},
                ],
                "component": {"type": "application", "bom-ref": "root", "group": "acme", "name": "ledger-core", "version": "1.1.0"},
            },
            "components": [
                {"type": "library", "bom-ref": "yaml", "purl": "pkg:maven/org.yaml/snakeyaml@1.30"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["yaml"]}],
        }
    )

    contract = merge_estate_observations([active_prod_doc, historical_doc, superseded_doc])
    app = contract["applications"][0]

    assert app["release"] == "1.2.0"
    assert app["active_versions"] == ["1.2.0"]
    assert app["active_builds"] == ["build-120"]
    assert contract["completeness"]["historical_builds_excluded"] == 2

    active_lids = {c["library_id"] for c in contract["components"]}
    assert active_lids == {"maven|org.springframework|spring-web|5.3.32"}
    assert "maven|commons-collections|commons-collections|3.2.1" not in active_lids
    assert "maven|org.yaml|snakeyaml|1.30" not in active_lids

    # Historical components remain auditable in historical_components and all_imported view
    hist_lids = {c["library_id"] for c in app["historical_components"]}
    assert hist_lids == {
        "maven|commons-collections|commons-collections|3.2.1",
        "maven|org.yaml|snakeyaml|1.30",
    }
    all_imported_view = evaluate_estate_view(contract, "all_imported")
    assert len(all_imported_view["components"]) == 3


def test_equivalent_spdx_and_cyclonedx_inputs_produce_identical_identities_and_counts() -> None:
    """Equivalent CycloneDX and SPDX inputs without explicit_app_id produce identical application/version/deployment identities and counts."""

    cdx_docs = [
        parse_cyclonedx_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "timestamp": "2026-10-20T10:00:00Z",
                    "properties": [
                        {"name": "osera:build_id", "value": f"build-{ver}"},
                        {"name": "osera:deployment_id", "value": f"deploy-prod-{region}"},
                        {"name": "osera:environment", "value": "production"},
                        {"name": "osera:region", "value": region},
                    ],
                    "component": {
                        "type": "application",
                        "bom-ref": "app-root",
                        "group": "acme",
                        "name": "settlement-worker",
                        "version": ver,
                        "externalReferences": [{"type": "vcs", "url": "https://github.com/acme/settlement-worker.git"}],
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "spring",
                        "purl": "pkg:maven/org.springframework/spring-web@5.3.20",
                    }
                ],
                "dependencies": [{"ref": "app-root", "dependsOn": ["spring"]}],
            }
        )
        for ver, region in [("1.0.0", "us-east-1"), ("2.0.0", "eu-west-1")]
    ]

    spdx_docs = [
        parse_spdx_document(
            {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "settlement-worker",
                "creationInfo": {
                    "created": "2026-10-20T10:00:00Z",
                    "comment": f"build_id=build-{ver};deployment_id=deploy-prod-{region};environment=production;region={region}",
                },
                "packages": [
                    {
                        "SPDXID": "SPDXRef-App",
                        "name": "acme/settlement-worker",
                        "versionInfo": ver,
                        "primaryPackagePurpose": "APPLICATION",
                        "DownloadLocation": "https://github.com/acme/settlement-worker.git",
                    },
                    {
                        "SPDXID": "SPDXRef-spring",
                        "name": "org.springframework:spring-web",
                        "versionInfo": "5.3.20",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:maven/org.springframework/spring-web@5.3.20",
                            }
                        ],
                    },
                ],
                "relationships": [
                    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-App"},
                    {"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-spring"},
                ],
            }
        )
        for ver, region in [("1.0.0", "us-east-1"), ("2.0.0", "eu-west-1")]
    ]

    cdx_contract = merge_estate_observations(cdx_docs)
    spdx_contract = merge_estate_observations(spdx_docs)

    assert [a["application_id"] for a in cdx_contract["applications"]] == ["github|acme|settlement-worker|main"]
    assert [a["application_id"] for a in spdx_contract["applications"]] == ["github|acme|settlement-worker|main"]

    cdx_app = cdx_contract["applications"][0]
    spdx_app = spdx_contract["applications"][0]
    assert cdx_app["name"] == spdx_app["name"] == "settlement-worker"
    assert cdx_app["project_ref"] == spdx_app["project_ref"] == "github/acme/settlement-worker"
    assert cdx_app["release"] == spdx_app["release"] == "2.0.0"
    assert cdx_app["active_production_versions"] == spdx_app["active_production_versions"] == ["1.0.0", "2.0.0"]
    assert [av["application_version_id"] for av in cdx_app["application_versions"]] == [
        av["application_version_id"] for av in spdx_app["application_versions"]
    ]
    assert cdx_app["deployments"] == spdx_app["deployments"]

    cdx_comp = cdx_contract["components"][0]
    spdx_comp = spdx_contract["components"][0]
    assert cdx_comp["library_id"] == spdx_comp["library_id"] == "maven|org.springframework|spring-web|5.3.20"
    assert cdx_comp["total_consumer_count"] == spdx_comp["total_consumer_count"] == 1
    assert cdx_comp["affected_application_version_count"] == spdx_comp["affected_application_version_count"] == 2
    assert cdx_comp["affected_deployment_count"] == spdx_comp["affected_deployment_count"] == 2


def test_public_export_strips_internal_qualifiers_and_subpaths_beyond_fixtures() -> None:
    """Packages with internal PURL qualifiers (`?build_id=...`) or subpaths (`#services/...`) never leak in public export."""

    doc = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-01T12:00:00Z",
                "properties": [
                    {"name": "osera:application_id", "value": "github|finbank|fx-pricing-service|main"},
                    {"name": "osera:build_id", "value": "payments-release-784"},
                    {"name": "osera:deployment_id", "value": "deploy-fx-prod-ny4"},
                    {"name": "osera:environment", "value": "production"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root-app",
                    "group": "finbank",
                    "name": "fx-pricing-service",
                    "version": "3.1.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "lib-1",
                    "purl": (
                        "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
                        "?arch=x86_64&build_id=payments-release-784&classifier=payments-release-784"
                        "&vcs_url=https://git.finbank.internal/services/payments-engine"
                        "#services/payments-engine"
                    ),
                },
                {
                    "type": "library",
                    "bom-ref": "lib-2",
                    "purl": (
                        "pkg:golang/github.com/gin-gonic/gin@1.9.1+build.payments-release-784"
                        "?commit=9a8b7c6d&distro=rhel-9.3&env=prod-ny4"
                        "#internal/pkg/fx-pricing-service/router"
                    ),
                },
            ],
            "dependencies": [
                {"ref": "root-app", "dependsOn": ["lib-1", "lib-2"]},
            ],
        }
    )

    contract = merge_estate_observations([doc])
    sanitized = sanitize_for_public_export(contract)
    serialized = json.dumps(sanitized)

    forbidden_internal_strings = [
        "build_id",
        "payments-release-784",
        "services/payments-engine",
        "payments-engine",
        "fx-pricing-service",
        "finbank",
        "deploy-fx-prod-ny4",
        "prod-ny4",
        "vcs_url",
        "9a8b7c6d",
        "internal/pkg",
    ]
    for token in forbidden_internal_strings:
        assert token not in serialized, f"Internal detail leaked into public export: {token!r}"

    libs_by_proj = {lib["proj"]: lib for lib in sanitized["libraries"]}
    log4j_pub = libs_by_proj["log4j-core"]
    assert log4j_pub["qualifiers"] == {"arch": ["x86_64"]}
    assert log4j_pub["subpaths"] == []
    assert log4j_pub["repackaged_internal_coordinates_redacted"] is True

    gin_pub = libs_by_proj["gin"]
    assert gin_pub["release"] == "1.9.1"
    assert gin_pub["qualifiers"] == {"distro": ["rhel-9.3"]}
    assert gin_pub["subpaths"] == []
    assert gin_pub["repackaged_internal_coordinates_redacted"] is True


def test_replacement_build_same_version_and_staging_build_same_version_isolation() -> None:
    """Replacement build b2 of the same app version 1.0.0 supersedes b1, and staging 1.0.0 never leaks into prod views."""

    # Production build b1 of app 1.0.0 uses Log4j 2.14.1
    prod_b1 = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-01T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "b1"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-main"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-11-01T10:00:00Z"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "risk-engine",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "log4j-old",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["log4j-old"]}],
        }
    )

    # Replacement production build b2 with the SAME app version (1.0.0) and SAME deployment uses Log4j 2.17.1
    prod_b2 = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-02T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "b2"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-main"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-11-02T10:00:00Z"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "risk-engine",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "log4j-fixed",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["log4j-fixed"]}],
        }
    )

    # Active staging build sharing the same app version (1.0.0) has a vulnerable staging-only dependency (snakeyaml 1.30)
    staging_b3 = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-03T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "b3-staging"},
                    {"name": "osera:deployment_id", "value": "deploy-staging-main"},
                    {"name": "osera:environment", "value": "staging"},
                    {"name": "osera:deployed_at", "value": "2026-11-03T10:00:00Z"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "risk-engine",
                    "version": "1.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "snakeyaml-vuln",
                    "purl": "pkg:maven/org.yaml/snakeyaml@1.30",
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["snakeyaml-vuln"]}],
        }
    )

    contract = merge_estate_observations([prod_b1, prod_b2, staging_b3])

    # 1. Superseded build b1 (log4j 2.14.1) must NOT appear in any active view
    active_deploy_lids = {c["library_id"] for c in evaluate_estate_view(contract, "all_active_deployments")["components"]}
    assert "maven|org.apache.logging.log4j|log4j-core|2.14.1" not in active_deploy_lids
    assert active_deploy_lids == {
        "maven|org.apache.logging.log4j|log4j-core|2.17.1",
        "maven|org.yaml|snakeyaml|1.30",
    }

    # 2. Production-only views must include ONLY replacement build b2 (log4j 2.17.1) and exclude both b1 (2.14.1) and staging b3 (snakeyaml 1.30)
    all_prod_lids = {c["library_id"] for c in evaluate_estate_view(contract, "all_active_production")["components"]}
    assert all_prod_lids == {"maven|org.apache.logging.log4j|log4j-core|2.17.1"}

    latest_prod_lids = {c["library_id"] for c in evaluate_estate_view(contract, "latest_production_version")["components"]}
    assert latest_prod_lids == {"maven|org.apache.logging.log4j|log4j-core|2.17.1"}

    # 3. Historical view (all_imported) still preserves b1 for auditability
    all_imported_lids = {c["library_id"] for c in evaluate_estate_view(contract, "all_imported")["components"]}
    assert all_imported_lids == {
        "maven|org.apache.logging.log4j|log4j-core|2.14.1",
        "maven|org.apache.logging.log4j|log4j-core|2.17.1",
        "maven|org.yaml|snakeyaml|1.30",
    }


def test_latest_version_selection_ranks_final_release_above_release_candidate() -> None:
    """With both 2.0.0-rc.1 and 2.0.0 active in production, latest_production_version selects 2.0.0."""

    prod_final = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-01T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-200-final"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-us"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-11-01T10:00:00Z"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "clearing-router",
                    "version": "2.0.0",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "log4j-safe",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["log4j-safe"]}],
        }
    )

    prod_rc = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                # Deliberately given a newer timestamp to ensure version precedence beats timestamp
                "timestamp": "2026-11-05T15:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-200-rc1"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-canary"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:deployed_at", "value": "2026-11-05T15:00:00Z"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "clearing-router",
                    "version": "2.0.0-rc.1",
                },
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "log4j-rc-vuln",
                    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                }
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["log4j-rc-vuln"]}],
        }
    )

    contract = merge_estate_observations([prod_final, prod_rc])
    app = contract["applications"][0]
    assert app["active_production_versions"] == ["2.0.0-rc.1", "2.0.0"]
    assert app["latest_production_version"] == "2.0.0"
    assert app["latest_version"] == "2.0.0"
    assert app["release"] == "2.0.0"

    latest_prod_view = evaluate_estate_view(contract, "latest_production_version")
    assert latest_prod_view["evaluated_application_version_ids"] == ["github|acme|clearing-router|main@2.0.0"]
    latest_lids = {c["library_id"] for c in latest_prod_view["components"]}
    assert latest_lids == {"maven|org.apache.logging.log4j|log4j-core|2.17.1"}
    assert "maven|org.apache.logging.log4j|log4j-core|2.14.1" not in latest_lids


def test_osera_java_patch_version_ordering_and_patch_sequences() -> None:
    """REL-003-JAVA OSERA patched versions rank after their numeric or qualified baselines, match Maven ComparableVersion, and keep SemVer scoped."""

    assert APPLICATION_VERSION_ORDERING_POLICY["policy_version"] == "osera-application-version-ordering/v1"

    # 1. Numeric-base and final-qualified Java examples:
    #    5.3.39 < 5.3.39.1-osera-00001 < 5.3.39.1-osera-00002
    #    2.0.0-final < 2.0.0-osera-0001 < 2.0.0-osera-0002
    #    2.0.0.Final < 2.0.0.Final-osera-00001 < 2.0.0.Final-osera-00002
    assert _version_sort_key("5.3.39", "maven") < _version_sort_key("5.3.39.1-osera-00001", "maven")
    assert _version_sort_key("5.3.39.1-osera-00001", "maven") < _version_sort_key("5.3.39.1-osera-00002", "maven")
    assert compare_application_versions("5.3.39", "5.3.39.1-osera-00001", "maven") == -1
    assert _version_sort_key("2.0.0-final", "maven") < _version_sort_key("2.0.0-osera-0001", "maven")
    assert _version_sort_key("2.0.0-osera-0001", "maven") < _version_sort_key("2.0.0-osera-0002", "maven")
    assert compare_application_versions("2.0.0-final", "2.0.0-osera-0001", "maven") == -1
    assert compare_application_versions("2.0.0-final", "2.0.0-osera-0001", "rel-003-java") == -1
    assert compare_application_versions("2.0.0-final", "2.0.0-osera-0001", "care") == -1
    assert _version_sort_key("2.0.0.Final", "maven") < _version_sort_key("2.0.0.Final-osera-00001", "maven")

    # 2. Qualified Java examples: 5.6.15.Final < 5.6.15.Final-osera-00001 and 2.0.0.RELEASE < 2.0.0.RELEASE-osera-00001
    assert _version_sort_key("5.6.15.Final", "maven") < _version_sort_key("5.6.15.Final-osera-00001", "maven")
    assert _version_sort_key("5.6.15.Final-osera-00001", "maven") < _version_sort_key("5.6.15.Final-osera-00002", "maven")
    assert _version_sort_key("2.0.0.RELEASE", "maven") < _version_sort_key("2.0.0.RELEASE-osera-00001", "maven")
    assert _version_sort_key("2.0.0.RELEASE-osera-00001", "maven") < _version_sort_key("2.0.0.RELEASE-osera-00002", "maven")

    # 3. Date-qualified Jetty-style baseline + OSERA patch: 9.4.51.v20230217 < 9.4.51.v20230217-osera-00001 < 9.4.51.v20230218
    assert _version_sort_key("9.4.51.v20230217", "maven") < _version_sort_key("9.4.51.v20230217-osera-00001", "maven")
    assert _version_sort_key("9.4.51.v20230217-osera-00001", "maven") < _version_sort_key("9.4.51.v20230218", "maven")

    # 4. Maven qualifier aliases and equivalence: CR1 = RC1, a1 = alpha-1, b1 = beta-1, m1 = milestone-1, and final = ga = release = ""
    assert _version_sort_key("2.0.0-CR1", "maven") == _version_sort_key("2.0.0-RC1", "maven")
    assert compare_application_versions("2.0.0-CR1", "2.0.0-RC1", "maven") == 0
    assert _version_sort_key("5.6.15.CR1", "maven") == _version_sort_key("5.6.15.RC1", "maven")
    assert compare_application_versions("5.6.15.CR1", "5.6.15.RC1", "maven") == 0
    assert compare_application_versions("2.0.0-a1", "2.0.0-alpha-1", "maven") == 0
    assert compare_application_versions("2.0.0-b1", "2.0.0-beta-1", "maven") == 0
    assert compare_application_versions("2.0.0-m1", "2.0.0-milestone-1", "maven") == 0
    assert compare_application_versions("2.0.0-final", "2.0.0", "maven") == 0
    assert compare_application_versions("2.0.0.Final", "2.0.0.RELEASE", "maven") == 0
    assert compare_application_versions("2.0.0.RELEASE", "2.0.0-GA", "maven") == 0

    # 5. Maven qualifier ordering: alpha < beta < milestone < rc = cr < snapshot < final < sp < osera < numeric build
    assert compare_application_versions("2.0.0-rc1", "2.0.0-SNAPSHOT", "maven") == -1
    assert compare_application_versions("2.0.0-SNAPSHOT", "2.0.0-final", "maven") == -1
    maven_chain = [
        "5.6.15.Alpha1",
        "5.6.15.Beta1",
        "5.6.15.M1",
        "5.6.15.RC1",
        "5.6.15-SNAPSHOT",
        "5.6.15.Final",
        "5.6.15.Final-osera-00001",
        "5.6.15.Final-osera-00002",
    ]
    assert sorted(reversed(maven_chain), key=lambda v: _version_sort_key(v, "maven")) == maven_chain

    maven_full_chain = [
        "2.0.0-alpha-1",
        "2.0.0-beta-1",
        "2.0.0-milestone-1",
        "2.0.0-rc1",
        "2.0.0-SNAPSHOT",
        "2.0.0-final",
        "2.0.0-sp1",
        "2.0.0-osera-0001",
        "2.0.0-osera-0002",
        "2.0.0-1",
        "2.0.0-2",
    ]
    assert sorted(reversed(maven_full_chain), key=lambda v: _version_sort_key(v, "maven")) == maven_full_chain

    # 6. Explicit SemVer inputs retain genuine SemVer 2.0.0 §11 behavior:
    #    - 2.0.0-osera-00001 < 2.0.0 (hyphen suffix is a SemVer pre-release, NOT post-release)
    #    - 2.0.0-final < 2.0.0 (-final is a SemVer pre-release, NOT equivalent to 2.0.0)
    assert _version_sort_key("2.0.0-osera-00001", "semver") < _version_sort_key("2.0.0", "semver")
    assert compare_application_versions("2.0.0-osera-00001", "2.0.0", "semver") == -1
    assert _version_sort_key("2.0.0-final", "semver") < _version_sort_key("2.0.0", "semver")
    assert compare_application_versions("2.0.0-final", "2.0.0", "semver") == -1

    semver_spec_chain = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ]
    assert sorted(reversed(semver_spec_chain), key=lambda v: _version_sort_key(v, "semver")) == semver_spec_chain

    semver_chain = [
        "2.0.0-alpha.1",
        "2.0.0-beta.1",
        "2.0.0-final",
        "2.0.0-osera-00001",
        "2.0.0-osera-00002",
        "2.0.0-rc.1",
        "2.0.0-rc.2",
        "2.0.0",
    ]
    assert sorted(reversed(semver_chain), key=lambda v: _version_sort_key(v, "semver")) == semver_chain


def test_maven_versus_semver_numeric_hyphen_suffix_and_explicit_convention_policy() -> None:
    """Explicitly cover Maven vs SemVer interpretation of 2.0.0-1 and honest handling of ambiguous/unsupported schemes."""

    # Under SemVer: 2.0.0-1 is a numeric prerelease identifier and ranks BELOW 2.0.0
    assert _version_sort_key("2.0.0-1", "semver") < _version_sort_key("2.0.0", "semver")
    assert compare_application_versions("2.0.0-1", "2.0.0", "semver") == -1

    # Under Maven/Java: 2.0.0-1 is a post-release build/patch revision and ranks ABOVE 2.0.0
    assert _version_sort_key("2.0.0", "maven") < _version_sort_key("2.0.0-1", "maven")
    assert _version_sort_key("2.0.0-1", "maven") < _version_sort_key("2.0.0-2", "maven")
    assert compare_application_versions("2.0.0-1", "2.0.0", "maven") == 1

    # Do NOT assume an application uses Maven ordering merely because it consumes Java dependencies:
    # Without an explicit convention or pkg:maven root PURL, 2.0.0 vs 2.0.0-1 is flagged as ambiguous_convention.
    ambig_v1 = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-01T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-200"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-a"},
                    {"name": "osera:environment", "value": "production"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "polyglot-gateway",
                    "version": "2.0.0",
                },
            },
            "components": [
                {"type": "library", "bom-ref": "spring", "purl": "pkg:maven/org.springframework/spring-web@5.3.20"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["spring"]}],
        }
    )
    ambig_v2 = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-02T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "build-200-1"},
                    {"name": "osera:deployment_id", "value": "deploy-prod-b"},
                    {"name": "osera:environment", "value": "production"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "polyglot-gateway",
                    "version": "2.0.0-1",
                },
            },
            "components": [
                {"type": "library", "bom-ref": "jackson", "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.3"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["jackson"]}],
        }
    )

    ambig_contract = merge_estate_observations([ambig_v1, ambig_v2])
    ambig_app = ambig_contract["applications"][0]
    assert ambig_app["version_ordering_status"] == "ambiguous_convention"
    assert ambig_app["latest_production_version"] == ""
    assert ambig_app["latest_version"] == ""

    # Honest handling in latest_production_version view: retains both active releases instead of silently dropping one
    ambig_latest_view = evaluate_estate_view(ambig_contract, "latest_production_version")
    assert ambig_latest_view["latest_version_selection_status"] == "partial_ambiguous_or_unsupported"
    assert ambig_latest_view["ambiguous_latest_version_application_ids"] == ["github|acme|polyglot-gateway|main"]
    assert {c["library_id"] for c in ambig_latest_view["components"]} == {
        "maven|org.springframework|spring-web|5.3.20",
        "maven|com.fasterxml.jackson.core|jackson-databind|2.13.3",
    }

    # When explicit convention is provided (maven vs semver), 2.0.0 vs 2.0.0-1 resolves deterministically as Intended:
    feed_maven = parse_company_inventory_feed(
        {
            "applications": [
                {
                    "application_id": "github|acme|java-service|main",
                    "name": "java-service",
                    "version": "2.0.0",
                    "version_convention": "maven",
                    "build_id": "b-200",
                    "deployment_id": "d-prod-1",
                    "environment": "production",
                    "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.20", "direct": True}],
                },
                {
                    "application_id": "github|acme|java-service|main",
                    "name": "java-service",
                    "version": "2.0.0-1",
                    "version_convention": "maven",
                    "build_id": "b-200-1",
                    "deployment_id": "d-prod-2",
                    "environment": "production",
                    "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.32", "direct": True}],
                },
            ]
        }
    )
    maven_contract = merge_estate_observations(feed_maven)
    maven_app = maven_contract["applications"][0]
    assert maven_app["version_convention"] == "maven"
    assert maven_app["version_ordering_status"] == "ordered"
    assert maven_app["latest_production_version"] == "2.0.0-1"
    maven_latest_lids = {c["library_id"] for c in evaluate_estate_view(maven_contract, "latest_production_version")["components"]}
    assert maven_latest_lids == {"maven|org.springframework|spring-web|5.3.32"}

    feed_semver = parse_company_inventory_feed(
        {
            "applications": [
                {
                    "application_id": "github|acme|node-service|main",
                    "name": "node-service",
                    "version": "2.0.0",
                    "version_convention": "semver",
                    "build_id": "b-200",
                    "deployment_id": "d-prod-1",
                    "environment": "production",
                    "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.32", "direct": True}],
                },
                {
                    "application_id": "github|acme|node-service|main",
                    "name": "node-service",
                    "version": "2.0.0-1",
                    "version_convention": "semver",
                    "build_id": "b-200-1",
                    "deployment_id": "d-prod-2",
                    "environment": "production",
                    "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.20", "direct": True}],
                },
            ]
        }
    )
    semver_contract = merge_estate_observations(feed_semver)
    semver_app = semver_contract["applications"][0]
    assert semver_app["version_convention"] == "semver"
    assert semver_app["version_ordering_status"] == "ordered"
    assert semver_app["latest_production_version"] == "2.0.0"
    semver_latest_lids = {c["library_id"] for c in evaluate_estate_view(semver_contract, "latest_production_version")["components"]}
    assert semver_latest_lids == {"maven|org.springframework|spring-web@5.3.32".replace("@", "|")}

    # Explicit SemVer applications retain genuine SemVer behavior even when version strings use
    # `-osera-00001` or `-final` and even when the application consumes Java/Maven dependencies:
    for prerelease_ver in ("2.0.0-osera-00001", "2.0.0-final"):
        semver_entries = [
            {
                "application_id": "github|acme|semver-polyglot-app|main",
                "name": "semver-polyglot-app",
                "version": "2.0.0",
                "version_convention": "semver",
                "build_id": "b-200-normal",
                "deployment_id": "d-prod-normal",
                "environment": "production",
                "observed_at": "2026-11-01T10:00:00Z",
                "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.32", "direct": True}],
            },
            {
                "application_id": "github|acme|semver-polyglot-app|main",
                "name": "semver-polyglot-app",
                "version": prerelease_ver,
                "version_convention": "semver",
                "build_id": f"b-{prerelease_ver}",
                "deployment_id": "d-prod-prerelease",
                "environment": "production",
                "observed_at": "2026-11-09T10:00:00Z",
                "dependencies": [{"purl": "pkg:maven/org.springframework/spring-web@5.3.20", "direct": True}],
            },
        ]
        for ordered_entries in (semver_entries, list(reversed(semver_entries))):
            parsed_semver_feed = parse_company_inventory_feed({"applications": ordered_entries})
            explicit_semver_contract = merge_estate_observations(parsed_semver_feed)
            explicit_semver_app = explicit_semver_contract["applications"][0]
            assert explicit_semver_app["version_convention"] == "semver"
            assert explicit_semver_app["active_production_versions"] == [prerelease_ver, "2.0.0"]
            assert explicit_semver_app["latest_production_version"] == "2.0.0"
            latest_sem_view = evaluate_estate_view(explicit_semver_contract, "latest_production_version")
            assert {c["library_id"] for c in latest_sem_view["components"]} == {
                "maven|org.springframework|spring-web|5.3.32"
            }
            all_active_sem_view = evaluate_estate_view(explicit_semver_contract, "all_active_production")
            assert {c["library_id"] for c in all_active_sem_view["components"]} == {
                "maven|org.springframework|spring-web|5.3.20",
                "maven|org.springframework|spring-web|5.3.32",
            }

    # Unsupported / opaque version schemes (e.g. git commit SHAs) do not claim a fake universal latest version
    conv, src, status = resolve_application_version_convention("", "", ["a1b2c3d4e5f6", "f6e5d4c3b2a1"])
    assert conv == "unsupported"
    assert status == "unsupported_scheme"


def test_estate_latest_production_version_view_with_osera_patched_releases_and_all_active_preservation() -> None:
    """Exercise latest_production_version and all_active_production views across REL-003-JAVA and Maven qualifier examples regardless of import order."""

    cases = [
        ("numeric-app", "5.3.39", "5.3.39.1-osera-00001"),
        ("final-hyphen-app", "2.0.0-final", "2.0.0-osera-0001"),
        ("final-dot-app", "2.0.0.Final", "2.0.0.Final-osera-00001"),
        ("hibernate-app", "5.6.15.Final", "5.6.15.Final-osera-00001"),
        ("spring-release-app", "2.0.0.RELEASE", "2.0.0.RELEASE-osera-00001"),
        ("maven-snapshot-vs-rc-app", "2.0.0-rc1", "2.0.0-SNAPSHOT"),
    ]

    for app_name, baseline_ver, patched_ver in cases:
        baseline_doc = parse_cyclonedx_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    # Give unpatched baseline a NEWER observed_at timestamp so timestamp order cannot accidentally win
                    "timestamp": "2026-11-08T18:00:00Z",
                    "properties": [
                        {"name": "osera:build_id", "value": f"build-{baseline_ver}"},
                        {"name": "osera:deployment_id", "value": f"deploy-prod-us-{app_name}"},
                        {"name": "osera:environment", "value": "production"},
                        {"name": "osera:deployed_at", "value": "2026-11-08T18:00:00Z"},
                    ],
                    "component": {
                        "type": "application",
                        "bom-ref": "root",
                        "group": "acme",
                        "name": app_name,
                        "version": baseline_ver,
                        "purl": f"pkg:maven/com.acme/{app_name}@{baseline_ver}",
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "unpatched-dep",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    }
                ],
                "dependencies": [{"ref": "root", "dependsOn": ["unpatched-dep"]}],
            }
        )

        patched_doc = parse_cyclonedx_document(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "timestamp": "2026-11-02T09:00:00Z",
                    "properties": [
                        {"name": "osera:build_id", "value": f"build-{patched_ver}"},
                        {"name": "osera:deployment_id", "value": f"deploy-prod-eu-{app_name}"},
                        {"name": "osera:environment", "value": "production"},
                        {"name": "osera:deployed_at", "value": "2026-11-02T09:00:00Z"},
                    ],
                    "component": {
                        "type": "application",
                        "bom-ref": "root",
                        "group": "acme",
                        "name": app_name,
                        "version": patched_ver,
                        "purl": f"pkg:maven/com.acme/{app_name}@{patched_ver}",
                    },
                },
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "patched-dep",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
                    }
                ],
                "dependencies": [{"ref": "root", "dependsOn": ["patched-dep"]}],
            }
        )

        # Exercise both import orders: [baseline, patched] and [patched, baseline]
        for ordered_docs in ([baseline_doc, patched_doc], [patched_doc, baseline_doc]):
            contract = merge_estate_observations(ordered_docs)
            app = contract["applications"][0]
            assert app["version_convention"] == "maven"
            assert app["version_ordering_status"] == "ordered"
            assert app["active_production_versions"] == [baseline_ver, patched_ver]
            assert app["latest_production_version"] == patched_ver
            assert app["latest_version"] == patched_ver
            assert app["release"] == patched_ver

            # latest_production_version view must select ONLY the patched release and its dependency (2.17.1)
            latest_view = evaluate_estate_view(contract, "latest_production_version")
            assert latest_view["latest_version_selection_status"] == "complete"
            assert latest_view["evaluated_application_version_ids"] == [f"github|acme|{app_name}|main@{patched_ver}"]
            latest_lids = {c["library_id"] for c in latest_view["components"]}
            assert latest_lids == {"maven|org.apache.logging.log4j|log4j-core|2.17.1"}

            # all_active_production view must still retain BOTH releases and BOTH dependencies while both remain active
            all_active_view = evaluate_estate_view(contract, "all_active_production")
            assert set(all_active_view["evaluated_application_version_ids"]) == {
                f"github|acme|{app_name}|main@{baseline_ver}",
                f"github|acme|{app_name}|main@{patched_ver}",
            }
            all_active_lids = {c["library_id"] for c in all_active_view["components"]}
            assert all_active_lids == {
                "maven|org.apache.logging.log4j|log4j-core|2.14.1",
                "maven|org.apache.logging.log4j|log4j-core|2.17.1",
            }


def test_conflicting_multi_import_conventions_and_spdx_osera_comment_convention() -> None:
    """Conflicting conventions across imports are order-independent, and SPDX osera:version_convention is honored."""

    doc_maven = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-01T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "b-200"},
                    {"name": "osera:deployment_id", "value": "d-prod-1"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:version_convention", "value": "maven"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "mixed-convention-app",
                    "version": "2.0.0",
                },
            },
            "components": [
                {"type": "library", "bom-ref": "dep-1", "purl": "pkg:maven/org.springframework/spring-web@5.3.20"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["dep-1"]}],
        }
    )
    doc_semver = parse_cyclonedx_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "timestamp": "2026-11-02T10:00:00Z",
                "properties": [
                    {"name": "osera:build_id", "value": "b-200-1"},
                    {"name": "osera:deployment_id", "value": "d-prod-2"},
                    {"name": "osera:environment", "value": "production"},
                    {"name": "osera:version_convention", "value": "semver"},
                ],
                "component": {
                    "type": "application",
                    "bom-ref": "root",
                    "group": "acme",
                    "name": "mixed-convention-app",
                    "version": "2.0.0-1",
                },
            },
            "components": [
                {"type": "library", "bom-ref": "dep-2", "purl": "pkg:maven/org.springframework/spring-web@5.3.32"}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["dep-2"]}],
        }
    )

    for docs_order in ([doc_maven, doc_semver], [doc_semver, doc_maven]):
        conflict_contract = merge_estate_observations(docs_order)
        conflict_app = conflict_contract["applications"][0]
        assert conflict_app["version_convention"] == "ambiguous"
        assert conflict_app["version_convention_source"] == "conflicting_explicit_conventions"
        assert conflict_app["version_ordering_status"] == "ambiguous_convention"
        assert conflict_app["latest_production_version"] == ""
        latest_view = evaluate_estate_view(conflict_contract, "latest_production_version")
        assert latest_view["latest_version_selection_status"] == "partial_ambiguous_or_unsupported"
        assert {c["library_id"] for c in latest_view["components"]} == {
            "maven|org.springframework|spring-web|5.3.20",
            "maven|org.springframework|spring-web|5.3.32",
        }

        # Explicit caller override resolves conflicting document conventions deterministically
        resolved_maven = merge_estate_observations(
            docs_order,
            application_version_conventions={"mixed-convention-app": "maven"},
        )
        assert resolved_maven["applications"][0]["latest_production_version"] == "2.0.0-1"

    # SPDX creationInfo.comment osera:version_convention=maven key works end-to-end
    spdx_base = parse_spdx_document(
        {
            "spdxVersion": "SPDX-2.3",
            "name": "spdx-java-app",
            "documentNamespace": "https://acme.example/spdx/b-200",
            "creationInfo": {
                "created": "2026-11-01T10:00:00Z",
                "comment": "osera:environment=production; osera:deployment_id=spdx-prod-1; osera:version_convention=maven",
            },
            "documentDescribes": ["SPDXRef-App"],
            "packages": [
                {
                    "SPDXID": "SPDXRef-App",
                    "name": "spdx-java-app",
                    "versionInfo": "2.0.0",
                    "primaryPackagePurpose": "APPLICATION",
                },
                {
                    "SPDXID": "SPDXRef-Dep1",
                    "name": "spring-web",
                    "versionInfo": "5.3.20",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:maven/org.springframework/spring-web@5.3.20",
                        }
                    ],
                },
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep1"}
            ],
        }
    )
    spdx_patched = parse_spdx_document(
        {
            "spdxVersion": "SPDX-2.3",
            "name": "spdx-java-app",
            "documentNamespace": "https://acme.example/spdx/b-200-1",
            "creationInfo": {
                "created": "2026-11-02T10:00:00Z",
                "comment": "osera:environment=production; osera:deployment_id=spdx-prod-2; osera:version_convention=maven",
            },
            "documentDescribes": ["SPDXRef-App"],
            "packages": [
                {
                    "SPDXID": "SPDXRef-App",
                    "name": "spdx-java-app",
                    "versionInfo": "2.0.0-1",
                    "primaryPackagePurpose": "APPLICATION",
                },
                {
                    "SPDXID": "SPDXRef-Dep2",
                    "name": "spring-web",
                    "versionInfo": "5.3.32",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:maven/org.springframework/spring-web@5.3.32",
                        }
                    ],
                },
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-App", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep2"}
            ],
        }
    )
    spdx_contract = merge_estate_observations([spdx_patched, spdx_base])
    assert spdx_contract["applications"][0]["version_convention"] == "maven"
    assert spdx_contract["applications"][0]["latest_production_version"] == "2.0.0-1"


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

    def test_two_versions_simultaneously_in_prod(self) -> None:
        test_two_versions_simultaneously_deployed_in_production_and_view_semantics()

    def test_historical_build_exclusion(self) -> None:
        test_historical_or_superseded_build_is_excluded_from_active_components()

    def test_spdx_cyclonedx_equivalence(self) -> None:
        test_equivalent_spdx_and_cyclonedx_inputs_produce_identical_identities_and_counts()

    def test_public_export_internal_qualifiers_and_subpaths(self) -> None:
        test_public_export_strips_internal_qualifiers_and_subpaths_beyond_fixtures()

    def test_replacement_and_staging_build_isolation(self) -> None:
        test_replacement_build_same_version_and_staging_build_same_version_isolation()

    def test_final_release_ranks_above_rc(self) -> None:
        test_latest_version_selection_ranks_final_release_above_release_candidate()

    def test_osera_java_patch_version_ordering(self) -> None:
        test_osera_java_patch_version_ordering_and_patch_sequences()

    def test_maven_vs_semver_and_explicit_convention(self) -> None:
        test_maven_versus_semver_numeric_hyphen_suffix_and_explicit_convention_policy()

    def test_estate_latest_view_osera_patched_and_all_active(self) -> None:
        test_estate_latest_production_version_view_with_osera_patched_releases_and_all_active_preservation()

    def test_conflicting_conventions_and_spdx_comment_convention(self) -> None:
        test_conflicting_multi_import_conventions_and_spdx_osera_comment_convention()


if __name__ == "__main__":
    unittest.main()



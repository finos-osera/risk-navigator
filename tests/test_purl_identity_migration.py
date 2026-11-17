from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from common import (
    canonical_library_id,
    canonical_package_id,
    make_library_id,
    make_package_id,
    parse_library_id,
    parse_package_id,
)
from migrate_purl_identities import (
    DATASET_FILES,
    dataset_golden_summary,
    migrate_all,
    migrate_dataset_payload,
    migrate_package_only_id,
    migrate_versioned_id,
)
from purl_identity import (
    format_purl,
    is_version_range_or_unresolved,
    parse_purl_spec,
    same_artifact_purl,
    same_package_purl,
)
from validate_dataset import validate

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("ecosystem", "meta", "proj", "release", "expected_purl", "expected_pkg_purl"),
    [
        (
            "maven",
            "org.springframework",
            "spring-web",
            "5.3.39",
            "pkg:maven/org.springframework/spring-web@5.3.39",
            "pkg:maven/org.springframework/spring-web",
        ),
        (
            "npm",
            "@scope",
            "pkg-name",
            "1.2.3-rc.1+build.5",
            "pkg:npm/%40scope/pkg-name@1.2.3-rc.1+build.5",
            "pkg:npm/%40scope/pkg-name",
        ),
        (
            "npm",
            "",
            "lodash",
            "4.17.21",
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/lodash",
        ),
        (
            "pypi",
            "",
            "PyYAML",
            "6.0.1",
            "pkg:pypi/pyyaml@6.0.1",
            "pkg:pypi/pyyaml",
        ),
        (
            "rpm",
            "rhel",
            "xz",
            "5.4.5-1",
            "pkg:rpm/rhel/xz@5.4.5-1",
            "pkg:rpm/rhel/xz",
        ),
    ],
)
def test_purl_roundtrip_across_supported_ecosystems(
    ecosystem: str,
    meta: str,
    proj: str,
    release: str,
    expected_purl: str,
    expected_pkg_purl: str,
) -> None:
    lid = make_library_id(ecosystem, meta, proj, release)
    pid = make_package_id(ecosystem, meta, proj)
    assert lid == expected_purl
    assert pid == expected_pkg_purl

    parsed_spec = parse_purl_spec(lid, require_version=True)
    assert parsed_spec.valid is True
    assert parsed_spec.canonical_purl == expected_purl
    assert parsed_spec.package_purl == expected_pkg_purl

    ns_out, meta_out, proj_out, rel_out = parse_library_id(lid)
    assert ns_out == ecosystem
    assert meta_out == meta
    assert proj_out == ("pyyaml" if ecosystem == "pypi" else proj)
    assert rel_out == release

    p_ns, p_meta, p_proj = parse_package_id(pid)
    assert (p_ns, p_meta, p_proj) == (ns_out, meta_out, proj_out)


def test_legacy_pipe_identities_normalize_to_canonical_purls() -> None:
    assert (
        canonical_library_id("maven|org.springframework|spring-web|5.3.39")
        == "pkg:maven/org.springframework/spring-web@5.3.39"
    )
    assert (
        canonical_library_id("npm|@finos|perspective|v2.10.0")
        == "pkg:npm/%40finos/perspective@2.10.0"
    )
    assert (
        canonical_library_id("pypi||Friendly_BARD|V1.0.0")
        == "pkg:pypi/friendly-bard@1.0.0"
    )
    assert (
        canonical_package_id("maven|org.apache.logging.log4j|log4j-core")
        == "pkg:maven/org.apache.logging.log4j/log4j-core"
    )
    assert (
        canonical_package_id("npm|@finos|perspective")
        == "pkg:npm/%40finos/perspective"
    )


def test_non_package_and_ambiguous_identities_are_rejected() -> None:
    # Consumer project / repository scope IDs must never be misparsed as packages
    assert parse_library_id("github|finos|legend-studio") == ("", "", "", "")
    assert parse_package_id("github|finos|legend-studio") == ("", "", "")
    assert canonical_library_id("github|finos|legend-studio") == ""
    assert canonical_package_id("github|finos|legend-studio") == ""

    # Colon-delimited strings without pkg: scheme must be rejected by canonical_library_id
    assert canonical_library_id("maven:org.springframework:spring-web:5.3.39") == ""
    assert parse_purl_spec("https://example.org/not-a-purl").valid is False
    assert parse_purl_spec("pkg:maven/org.springframework/spring-web", require_version=True).valid is False


def test_qualifiers_subpaths_and_unresolved_ranges() -> None:
    purl_with_qual = "pkg:npm/%40scope/demo@1.2.3?arch=x64&os=linux#dist/index.js"
    parsed = parse_purl_spec(purl_with_qual, require_version=True)
    assert parsed.valid is True
    assert parsed.namespace == "@scope"
    assert parsed.name == "demo"
    assert parsed.version == "1.2.3"
    assert dict(parsed.qualifiers) == {"arch": "x64", "os": "linux"}
    assert parsed.subpath == "dist/index.js"

    assert same_artifact_purl(
        "pkg:npm/%40scope/demo@1.2.3?os=linux&arch=x64#dist/index.js",
        purl_with_qual,
    )
    assert not same_artifact_purl(
        "pkg:npm/%40scope/demo@1.2.3?arch=arm64#dist/index.js",
        purl_with_qual,
    )
    assert same_package_purl(
        "pkg:npm/%40scope/demo@1.2.3",
        "pkg:npm/%40scope/demo@2.0.0",
    )

    assert is_version_range_or_unresolved("^1.2.3") is True
    assert is_version_range_or_unresolved(">=1.0.0 <2.0.0") is True
    assert is_version_range_or_unresolved("${spring.version}") is True
    assert is_version_range_or_unresolved("unspecified") is True
    assert is_version_range_or_unresolved("5.3.39-osera.1") is False


def test_all_published_datasets_pass_purl_schema_validation_and_idempotence() -> None:
    data_dir = ROOT / "data"
    for filename in DATASET_FILES:
        path = data_dir / filename
        assert path.exists(), f"Expected dataset {filename}"
        errors = validate(path)
        assert errors == [], f"Validation errors in {filename}: {errors}"

        payload = json.loads(path.read_text(encoding="utf-8"))
        summary_before = dataset_golden_summary(payload)
        remigrated = migrate_dataset_payload(payload)
        assert remigrated == payload, f"Dataset migration must be idempotent for {filename}"
        assert dataset_golden_summary(remigrated) == summary_before

        # Consumer project IDs must remain non-PURL repository/project IDs
        for proj in payload.get("consumer_projects", []):
            assert not str(proj.get("id") or "").startswith("pkg:")

        # Library IDs must all be valid versioned PURLs
        for lib in payload.get("libraries", []):
            assert str(lib.get("id") or "").startswith("pkg:")
            assert parse_purl_spec(lib["id"], require_version=True).valid is True


def test_migration_script_check_mode_reports_zero_pending_files() -> None:
    changed_csvs, changed_datasets = migrate_all(ROOT, write=False)
    assert changed_csvs == []
    assert changed_datasets == []

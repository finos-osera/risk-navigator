from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.patch_feeds import (
    evaluate_estate_patch_adoption,
    extract_osera_maintenance_line,
    filter_estate_patch_records,
    load_patch_feeds,
    parse_purl,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "data" / "fixtures" / "patch-feeds-estate-sample.json"


def _load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_parse_purl_and_osera_maintenance_line_alignment() -> None:
    parsed = parse_purl("pkg:maven/at.yawk.lz4/lz4-java@1.8.1.1-osera-00001")
    assert parsed["valid"] is True
    assert parsed["ecosystem"] == "Java"
    assert parsed["library"] == "at.yawk.lz4:lz4-java"
    assert parsed["version"] == "1.8.1.1-osera-00001"

    line = extract_osera_maintenance_line(parsed["version"])
    assert line == {
        "base_version": "1.8.1.1",
        "maintenance_line": "1.8.x",
        "sequence": 1,
    }

    scoped_npm = parse_purl("pkg:npm/%40scope/demo@1.2.3?arch=x64#subpath")
    assert scoped_npm["valid"] is True
    assert scoped_npm["library"] == "@scope:demo"
    assert scoped_npm["version"] == "1.2.3"
    assert scoped_npm["ecosystem"] == "JavaScript"

    non_purl = parse_purl("https://example.org/non-purl-artifact")
    assert non_purl["valid"] is False
    assert "Unsupported or non-PURL" in non_purl["error"]


def test_loads_osera_openvex_and_provider_catalog_with_provenance_and_ambiguous_records() -> None:
    raw = _load_fixture()
    catalog = load_patch_feeds(raw["feeds"])

    assert len(catalog["feeds"]) == 2
    osera_feed = next(f for f in catalog["feeds"] if f["feed_id"] == "osera-openvex")
    member_feed = next(f for f in catalog["feeds"] if f["feed_id"] == "member-catalog-v1")

    assert osera_feed["adapter"] == "osera_openvex"
    assert osera_feed["ambiguous_record_count"] == 1
    assert len(catalog["ambiguous_records"]) == 1
    assert catalog["ambiguous_records"][0]["product_id"] == "https://example.org/non-purl-artifact"

    assert member_feed["adapter"] == "provider_catalog"
    assert member_feed["validation_errors"] == []

    # Overlapping patch across both feeds preserves multi-feed provenance without duplicating the patch entry
    lz4_patch = next(
        p
        for p in catalog["patches"]
        if p["replacement_purl"] == "pkg:maven/at.yawk.lz4/lz4-java@1.8.1.1-osera-00001"
    )
    assert len(lz4_patch["provenance"]) == 2
    assert {prov["feed_id"] for prov in lz4_patch["provenance"]} == {
        "osera-openvex",
        "member-catalog-v1",
    }

    # Older numeric -osera-00001 tag on spring-boot-autoconfigure 2.7.18 is marked superseded by -osera-00002
    sb_old = next(
        p
        for p in catalog["patches"]
        if p["replacement_purl"]
        == "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.7.18-osera-00001"
    )
    assert (
        sb_old["superseded_by"]
        == "pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.7.18-osera-00002"
    )


def test_estate_evaluation_covers_all_five_states_and_deduplicates_consumers() -> None:
    raw = _load_fixture()
    result = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])

    pkg_by_lib = {p["library"]: p for p in result["package_summaries"]}

    # 1. Available unconsumed patch (at.yawk.lz4:lz4-java)
    lz4 = pkg_by_lib["at.yawk.lz4:lz4-java"]
    assert lz4["adoption_state"] == "applicable_unadopted"
    # app-trading-core has both direct and transitive edges to lz4-java@1.8.1.1; must be deduplicated
    assert lz4["application_ids"] == ["app-risk-engine", "app-trading-core"]
    assert lz4["instance_count"] == 2
    assert lz4["potential_cves"] == ["CVE-2025-66566"]

    # 2. Observed patched artifact (org.springframework.boot:spring-boot-autoconfigure)
    sb = pkg_by_lib["org.springframework.boot:spring-boot-autoconfigure"]
    assert sb["adoption_state"] == "observed_patched"
    assert sb["observed_patched_applications"] == ["app-trading-core"]
    assert sb["addressed_cves"] == ["CVE-2024-38816"]

    # 3. Partially adopted patch (io.netty:netty-codec-http2)
    netty = pkg_by_lib["io.netty:netty-codec-http2"]
    assert netty["adoption_state"] == "partially_adopted"
    assert netty["observed_patched_applications"] == ["app-trading-core"]
    assert netty["unadopted_applications"] == ["app-settlement-gateway"]

    # 4. Coverage gap / no known patch (com.google.guava:guava)
    guava = pkg_by_lib["com.google.guava:guava"]
    assert guava["adoption_state"] == "no_known_patch"
    assert guava["residual_cves"] == ["CVE-2023-2976"]

    # 5. Unknown identity (internal-custom://unmapped-binary-blob)
    unknown_recs = [
        r for r in result["instance_records"] if r["instance_state"] == "unknown_evidence"
    ]
    assert len(unknown_recs) == 1
    assert unknown_recs[0]["application_id"] == "app-legacy-adapter"


def test_vex_not_affected_unreleased_withdrawn_and_digest_mismatch_never_inflate_counts() -> None:
    raw = _load_fixture()
    result = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])

    guava_rec = next(
        r for r in result["instance_records"] if r["library"] == "com.google.guava:guava"
    )
    # Guava has VEX not_affected (CVE-2020-8908), VEX under_investigation (CVE-2023-2976),
    # a 'planned' patch, and a 'withdrawn' patch — none may count as an available released patch.
    assert guava_rec["instance_state"] == "no_known_patch"
    assert guava_rec["applicable_patches"] == []
    blocked_reasons = {b["blocked_reason"] for b in guava_rec["blocked_candidates"]}
    assert "unreleased_work:planned" in blocked_reasons
    assert "withdrawn_artifact" in blocked_reasons
    vex_statuses = {v["status"] for v in guava_rec["vex_assessments"]}
    assert vex_statuses == {"not_affected", "under_investigation"}

    # Tamper with the observed artifact_digest on spring-boot-autoconfigure: must NOT count as observed_patched
    tampered = _load_fixture()
    sb_comp = tampered["estate_snapshot"]["applications"][0]["components"][2]
    sb_comp["artifact_digest"] = "sha256:000000000000000000000000000000000000000000000000000000000000dead"
    tampered_result = evaluate_estate_patch_adoption(
        tampered["estate_snapshot"], tampered["feeds"]
    )
    sb_rec = next(
        r
        for r in tampered_result["instance_records"]
        if r["library"] == "org.springframework.boot:spring-boot-autoconfigure"
    )
    assert sb_rec["instance_state"] == "applicable_unadopted"
    assert any(
        b["blocked_reason"] == "artifact_digest_mismatch" for b in sb_rec["blocked_candidates"]
    )


def test_metrics_denominators_stale_tracking_and_zero_eligible_not_applicable() -> None:
    raw = _load_fixture()
    result = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])
    m = result["metrics"]

    assert m["observation_basis"] == "sbom_build_observation_not_verified_runtime"
    # 3 of 4 applications have an available patch (trading-core, risk-engine, settlement-gateway)
    assert m["applications_with_available_patch"]["numerator"] == 3
    assert m["applications_with_available_patch"]["denominator"] == 4
    # 1 of 4 applications has observed patch use (trading-core)
    assert m["applications_with_observed_patch_use"]["numerator"] == 1
    assert m["applications_with_observed_patch_use"]["denominator"] == 4
    # 2 of 6 eligible component instances are observed_patched
    assert m["patched_eligible_component_instances"]["numerator"] == 2
    assert m["patched_eligible_component_instances"]["denominator"] == 6
    assert m["stale_observation_count"] == 1
    assert m["unknown_observation_count"] == 1

    # Zero eligible component instances must produce explicit 'not_applicable'
    empty_estate = {
        "snapshot_id": "empty-estate",
        "snapshot_date": "2026-10-28T18:00:00Z",
        "applications": [
            {
                "application_id": "app-only-unknown",
                "observed_at": "2026-10-28T18:00:00Z",
                "components": [{"purl": "invalid://not-a-purl", "cves": []}],
            }
        ],
    }
    empty_res = evaluate_estate_patch_adoption(empty_estate, raw["feeds"])
    inst_metric = empty_res["metrics"]["patched_eligible_component_instances"]
    assert inst_metric["status"] == "not_applicable"
    assert inst_metric["ratio"] is None
    assert "Not applicable" in inst_metric["display"]


def test_idempotent_refresh_and_estate_adoption_progression() -> None:
    raw = _load_fixture()
    baseline = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])

    # Duplicating feeds and component observations must be 100% idempotent
    duplicated_feeds = raw["feeds"] + copy.deepcopy(raw["feeds"])
    dup_estate = copy.deepcopy(raw["estate_snapshot"])
    dup_estate["applications"][0]["components"].extend(
        copy.deepcopy(dup_estate["applications"][0]["components"])
    )
    repeated = evaluate_estate_patch_adoption(dup_estate, duplicated_feeds)
    assert repeated["metrics"] == baseline["metrics"]

    # Refreshing estate snapshot after app-settlement-gateway adopts the Netty OSERA patch updates adoption
    updated_estate = copy.deepcopy(raw["estate_snapshot"])
    netty_comp = updated_estate["applications"][2]["components"][0]
    netty_comp["purl"] = "pkg:maven/io.netty/netty-codec-http2@4.1.100.Final-osera-00001"
    netty_comp["artifact_digest"] = (
        "sha256:9999999999999999999999999999999999999999999999999999999999999999"
    )
    progressed = evaluate_estate_patch_adoption(updated_estate, raw["feeds"])
    assert progressed["metrics"]["applications_with_observed_patch_use"]["numerator"] == 2
    assert progressed["metrics"]["patched_eligible_component_instances"]["numerator"] == 3
    netty_pkg = next(
        p for p in progressed["package_summaries"] if p["library"] == "io.netty:netty-codec-http2"
    )
    assert netty_pkg["adoption_state"] == "observed_patched"


def test_filtering_and_uncovered_demand_cart_export_and_ui_hook() -> None:
    raw = _load_fixture()
    result = evaluate_estate_patch_adoption(raw["estate_snapshot"], raw["feeds"])

    partial = filter_estate_patch_records(result, adoption_state="partially_adopted")
    assert len(partial) == 2
    assert {r["application_id"] for r in partial} == {
        "app-trading-core",
        "app-settlement-gateway",
    }

    by_cve = filter_estate_patch_records(result, advisory_id="CVE-2025-66566")
    assert {r["application_id"] for r in by_cve} == {"app-trading-core", "app-risk-engine"}

    cart = result["uncovered_demand_cart"]
    assert len(cart) == 1
    assert cart[0]["Package"] == "com.google.guava:guava"
    assert cart[0]["CVEs"] == ["CVE-2023-2976"]
    assert cart[0]["AffectedApplications"] == ["app-settlement-gateway"]

    html = (ROOT / "tool" / "risk-navigator.html").read_text(encoding="utf-8")
    assert "function renderPatchFeedAdoptionDashboard(dataset)" in html
    assert "${renderPatchFeedAdoptionDashboard(state.dataset)}" in html


def test_cross_feed_conflicts_and_disabled_feeds_are_isolated() -> None:
    raw = _load_fixture()
    # Disable the second feed: only osera-openvex should remain active in provenance
    disabled_bundle = copy.deepcopy(raw["feeds"])
    disabled_bundle[1]["config"]["enabled"] = False
    disabled_cat = load_patch_feeds(disabled_bundle)
    lz4_patch = next(
        p
        for p in disabled_cat["patches"]
        if p["replacement_purl"] == "pkg:maven/at.yawk.lz4/lz4-java@1.8.1.1-osera-00001"
    )
    assert len(lz4_patch["provenance"]) == 1
    assert lz4_patch["provenance"][0]["feed_id"] == "osera-openvex"

    # Introduce a cross-feed artifact_digest disagreement between osera-openvex and member-catalog-v1
    conflicting_bundle = copy.deepcopy(raw["feeds"])
    conflicting_bundle[1]["document"]["patches"][0]["artifact_digest"] = (
        "sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
    )
    conflict_eval = evaluate_estate_patch_adoption(
        raw["estate_snapshot"], conflicting_bundle
    )
    assert len(conflict_eval["feed_conflicts"]) == 1
    assert (
        conflict_eval["feed_conflicts"][0]["reason"]
        == "Cross-feed artifact_digest disagreement"
    )
    # Because the two feeds disagree on the digest for lz4-java@1.8.1.1-osera-00001,
    # lz4-java instances must surface as 'unknown_evidence' rather than silently picking one feed.
    lz4_recs = [
        r
        for r in conflict_eval["instance_records"]
        if r["library"] == "at.yawk.lz4:lz4-java"
    ]
    assert all(r["instance_state"] == "unknown_evidence" for r in lz4_recs)


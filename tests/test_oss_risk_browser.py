import json
import re
import subprocess
from pathlib import Path


BROWSER_PATH = Path(__file__).resolve().parents[1] / "oss-risk" / "browser.html"
DOCS_PATH = Path(__file__).resolve().parents[1] / "docs" / "oss-risk.mdx"


def _extract_inline_script() -> str:
    html = BROWSER_PATH.read_text(encoding="utf-8")
    match = re.search(r"<script>([\s\S]*?)</script>", html)
    assert match, "Expected inline <script> in oss-risk/browser.html"
    script = match.group(1)
    # Strip the top-level DOM bootstrap at the bottom so pure rendering functions can be tested in Node
    cutoff = script.find("const recordsBody = document.getElementById")
    assert cutoff != -1, "Expected DOM element bindings in oss-risk/browser.html"
    head = script[:cutoff]
    tail_start = script.find("function clamp(value")
    tail_end = script.find("searchInput.addEventListener")
    assert tail_start != -1 and tail_end != -1
    body = script[tail_start:tail_end]
    return head + "\n" + body


def _eval_render_sources(record: dict) -> str:
    js_code = (
        _extract_inline_script()
        + "\nconst record = "
        + json.dumps(record)
        + ";\nconsole.log(renderSources(record));\n"
    )
    proc = subprocess.run(
        ["node", "-e", js_code],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def test_unified_vulnerability_intelligence_card_with_kev_matches_defaults_to_kev_tab():
    record = {
        "_id": "maven:org.apache.logging.log4j:log4j-core",
        "project": {
            "name": "Apache Log4j 2",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "evidence": {
            "osv": {
                "source": "osv-query-api",
                "url": "https://api.osv.dev/v1/query",
                "observed_at": "2026-08-11T17:52:27Z",
                "confidence": 0.9,
                "vulnerability_count": 11,
                "cve_count": 11,
                "cves": ["CVE-2021-44228", "CVE-2021-45046"],
                "vulnerabilities": [
                    {
                        "id": "GHSA-jfh8-c2jp-5v3q",
                        "summary": "Remote code injection in Log4j",
                        "aliases": ["CVE-2021-44228"],
                    }
                ],
            },
            "cisa_kev": {
                "source": "cisa-kev-json",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "observed_at": "2026-08-11T17:52:27Z",
                "confidence": 0.95,
                "catalog_count": 1662,
                "matched_count": 2,
                "matches": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j2",
                        "dateAdded": "2021-12-10",
                        "shortDescription": "Apache Log4j2 JNDI RCE.",
                    }
                ],
            },
        },
    }
    rendered = _eval_render_sources(record)
    assert len(re.findall(r'<div class="source(?:\s+(?:alert|muted))?">', rendered)) == 1
    assert 'class="source alert"' in rendered
    assert "Vulnerability Intelligence" in rendered
    assert "OSV records" in rendered
    assert "CVE aliases" in rendered
    assert "CISA KEV matches" in rendered
    assert "Collector confidence" in rendered
    assert ">OSV</a>" in rendered
    assert ">CISA KEV catalog</a>" in rendered
    assert 'data-vuln-tab="kev"' in rendered
    assert re.search(r'data-vuln-tab="kev"[\s\S]*?aria-selected="true"', rendered)
    assert re.search(r'data-vuln-tab="osv"[\s\S]*?aria-selected="false"', rendered)
    assert "vulnerability-scroll" in rendered


def test_unified_vulnerability_intelligence_card_without_kev_matches_defaults_to_osv_tab():
    record = {
        "_id": "maven:com.fasterxml.jackson.core:jackson-databind",
        "project": {
            "name": "Jackson Databind",
            "ecosystem": "maven",
            "package": "com.fasterxml.jackson.core:jackson-databind",
        },
        "evidence": {
            "osv": {
                "source": "osv-query-api",
                "observed_at": "2026-08-11T17:52:27Z",
                "confidence": 0.9,
                "vulnerability_count": 3,
                "cve_count": 3,
                "cves": ["CVE-2022-42003"],
                "vulnerabilities": [
                    {
                        "id": "GHSA-jjjh-jjxp-wpff",
                        "summary": "Deep wrapper array nesting in jackson-databind",
                        "aliases": ["CVE-2022-42003"],
                    }
                ],
            },
            "cisa_kev": {
                "source": "cisa-kev-json",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "confidence": 0.95,
                "catalog_count": 1662,
                "matched_count": 0,
                "matches": [],
            },
        },
    }
    rendered = _eval_render_sources(record)
    assert len(re.findall(r'<div class="source(?:\s+(?:alert|muted))?">', rendered)) == 1
    assert 'class="source"' in rendered
    assert re.search(r'data-vuln-tab="osv"[\s\S]*?aria-selected="true"', rendered)
    assert re.search(r'data-vuln-tab="kev"[\s\S]*?aria-selected="false"', rendered)
    assert "No OSV CVE aliases for this package matched the CISA Known Exploited Vulnerabilities catalog." in rendered


def test_unified_vulnerability_intelligence_card_osv_not_applicable_disables_kev_tab():
    record = {
        "_id": "system:openssl",
        "project": {
            "name": "OpenSSL",
            "ecosystem": "system",
            "package": "openssl",
        },
        "evidence": {
            "osv": {
                "source": "not-applicable",
                "confidence": 0.0,
            },
            "cisa_kev": {
                "source": "disabled",
                "confidence": 0.0,
                "matched_count": 0,
            },
        },
    }
    rendered = _eval_render_sources(record)
    assert len(re.findall(r'<div class="source(?:\s+(?:alert|muted))?">', rendered)) == 1
    assert 'class="source muted"' in rendered
    assert "OSV needs a concrete distro ecosystem for system packages" in rendered
    assert re.search(r'data-vuln-tab="osv"[\s\S]*?aria-selected="true"', rendered)
    assert re.search(r'data-vuln-tab="kev"[\s\S]*?aria-disabled="true"', rendered)


def test_methodology_and_docs_describe_unified_vulnerability_intelligence_card():
    browser_html = BROWSER_PATH.read_text(encoding="utf-8")
    docs_mdx = " ".join(DOCS_PATH.read_text(encoding="utf-8").split())
    assert "Vulnerability Intelligence" in browser_html
    assert "derived from OSV CVE aliases" in browser_html
    assert "OSERA OpenVEX" in browser_html
    assert "https://feed.finos.org/openvex.json" in browser_html
    assert "Vulnerability Intelligence" in docs_mdx
    assert "derived from OSV CVE aliases" in docs_mdx
    assert "https://feed.finos.org/openvex.json" in docs_mdx


def test_unified_vulnerability_intelligence_card_renders_osera_openvex_tab_and_distinguishes_uncovered_packages():
    covered_record = {
        "_id": "maven:org.apache.logging.log4j:log4j-core",
        "project": {
            "name": "Apache Log4j 2",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "evidence": {
            "finos_osera_backpatch": {
                "source": "github-org-discovery",
                "url": "https://github.com/finos-osera/backpatch-log4j2",
                "observed_at": "2026-08-11T17:29:00Z",
                "confidence": 0.9,
                "backpatch_repository": "finos-osera/backpatch-log4j2",
                "backpatch_name": "backpatch-log4j2",
                "library_name": "log4j-core",
                "is_fork": True,
                "is_archived": False,
                "coordinate_source": "override",
                "upstream_repository": "https://github.com/apache/logging-log4j2",
                "published_osera_patch_available": True,
                "published_osera_patch_count": 2,
                "published_osera_versions": ["2.12.4-osera.1", "2.3.2-osera.1"],
            },
            "osv": {
                "source": "osv-query-api",
                "url": "https://api.osv.dev/v1/query",
                "observed_at": "2026-11-04T02:35:00Z",
                "confidence": 0.9,
                "vulnerability_count": 11,
                "cve_count": 11,
                "cves": ["CVE-2021-44228", "CVE-2021-45046"],
                "vulnerabilities": [
                    {
                        "id": "GHSA-jfh8-c2jp-5v3q",
                        "summary": "Remote code injection in Log4j",
                        "aliases": ["CVE-2021-44228"],
                    }
                ],
            },
            "cisa_kev": {
                "source": "cisa-kev-json",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "observed_at": "2026-11-04T02:35:00Z",
                "confidence": 0.95,
                "catalog_count": 1662,
                "matched_count": 1,
                "matches": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j2",
                        "dateAdded": "2021-12-10",
                        "shortDescription": "Apache Log4j2 JNDI RCE.",
                    }
                ],
            },
            "osera_openvex": {
                "source": "osera-openvex-json",
                "url": "https://feed.finos.org/openvex.json",
                "observed_at": "2026-11-04T02:35:00Z",
                "retrieved_at": "2026-11-04T02:35:00Z",
                "feed_version": 161,
                "feed_last_updated": "2026-11-02T15:22:11Z",
                "coverage_status": "published_patch_available",
                "statement_count": 4,
                "deduplicated_statement_count": 2,
                "published_patch_count": 2,
                "fixed_advisory_count": 2,
                "fixed_cve_count": 2,
                "fixed_cves": ["CVE-2021-44228", "CVE-2021-45046"],
                "published_patches": [
                    {
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1",
                        "version": "2.12.4-osera.1",
                        "supplier": "OSERA",
                        "timestamp": "2026-11-02T15:22:11Z",
                        "statement_count": 2,
                        "fixed_advisory_count": 2,
                        "fixed_advisories": ["CVE-2021-44228", "CVE-2021-45046"],
                        "fixed_cve_count": 2,
                        "fixed_cves": ["CVE-2021-44228", "CVE-2021-45046"],
                    }
                ],
                "installed_version_claims": [
                    {
                        "installed_version": "2.12.4-osera.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1",
                        "osera_patch_matched": True,
                        "status": "fixed_by_osera_patch",
                        "fixed_advisories": ["CVE-2021-44228", "CVE-2021-45046"],
                        "fixed_cves": ["CVE-2021-44228", "CVE-2021-45046"],
                    }
                ],
                "confidence": 0.95,
            },
        },
    }
    rendered_covered = _eval_render_sources(covered_record)
    # 2 source cards total: finos_osera_backpatch + unified Vulnerability Intelligence (osera_openvex and cisa_kev are folded in)
    assert len(re.findall(r'<div class="source(?:\s+(?:alert|muted))?">', rendered_covered)) == 2
    assert ">OSERA OpenVEX feed</a>" in rendered_covered
    assert 'data-vuln-tab="openvex"' in rendered_covered
    assert "2.12.4-osera.1" in rendered_covered
    assert "feed v161" in rendered_covered
    assert "2 deduplicated / 4 raw statement(s)" in rendered_covered
    assert "published in OpenVEX" in rendered_covered

    uncovered_record = {
        "_id": "maven:org.jodd:jodd-json",
        "project": {
            "name": "jodd-json",
            "ecosystem": "maven",
            "package": "org.jodd:jodd-json",
        },
        "evidence": {
            "finos_osera_backpatch": {
                "source": "github-org-discovery",
                "backpatch_repository": "finos-osera/backpatch-jodd-json",
                "published_osera_patch_available": False,
                "published_osera_patch_count": 0,
            },
            "osv": {
                "source": "osv-query-api",
                "confidence": 0.9,
                "vulnerability_count": 1,
                "cve_count": 1,
                "cves": ["CVE-2018-21234"],
                "vulnerabilities": [{"id": "GHSA-jrg3-qq99-35g7", "aliases": ["CVE-2018-21234"]}],
            },
            "cisa_kev": {
                "source": "cisa-kev-json",
                "confidence": 0.95,
                "catalog_count": 1662,
                "matched_count": 0,
                "matches": [],
            },
            "osera_openvex": {
                "source": "osera-openvex-json",
                "url": "https://feed.finos.org/openvex.json",
                "coverage_status": "no_published_osera_fix",
                "published_patch_count": 0,
                "published_patches": [],
                "confidence": 0.95,
            },
        },
    }
    rendered_uncovered = _eval_render_sources(uncovered_record)
    assert "No published OSERA fix was found in" in rendered_uncovered
    assert "absence from the OpenVEX feed does not mean zero vulnerabilities" in rendered_uncovered
    assert "fork repo != published patch" in rendered_uncovered


def test_collect_osera_openvex_matching_deduplication_unavailable_and_cache_timestamp(tmp_path):
    import importlib.util
    from datetime import datetime, timezone

    collector_path = Path(__file__).resolve().parents[1] / "oss-risk" / "collectors" / "collect_oss_risk.py"
    spec = importlib.util.spec_from_file_location("collect_oss_risk", collector_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    sample_feed = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://osera.finos.org/vex/openvex-test",
        "author": "FINOS OSERA",
        "version": 161,
        "timestamp": "2026-10-01T00:00:00Z",
        "last_updated": "2026-11-02T15:22:11Z",
        "statements": [
            {
                "vulnerability": {"name": "CVE-2021-44228"},
                "timestamp": "2026-10-15T10:00:00Z",
                "products": [
                    {
                        "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1",
                        "identifiers": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1"},
                        "supplier": "OSERA",
                    }
                ],
                "status": "fixed",
            },
            # Duplicate historical statement for the same (purl, vuln_id, status, supplier) with newer timestamp
            {
                "vulnerability": {"name": "CVE-2021-44228"},
                "timestamp": "2026-11-02T15:22:11Z",
                "products": [
                    {
                        "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1",
                        "identifiers": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.4-osera.1"},
                        "supplier": "OSERA",
                    }
                ],
                "status": "fixed",
            },
            # Different package (log4j:log4j 1.x) must not match org.apache.logging.log4j:log4j-core
            {
                "vulnerability": {"name": "CVE-2019-17571"},
                "timestamp": "2026-11-01T00:00:00Z",
                "products": [
                    {
                        "@id": "pkg:maven/log4j/log4j@1.2.17-osera.1",
                        "identifiers": {"purl": "pkg:maven/log4j/log4j@1.2.17-osera.1"},
                        "supplier": "OSERA",
                    }
                ],
                "status": "fixed",
            },
        ],
    }

    import hashlib

    client = mod.HttpClient(tmp_path / "cache", refresh=False)
    # Seed cache file + .meta.json sidecar with an explicit historical timestamp
    cache_key = hashlib.sha256(b"GET\0" + mod.OSERA_OPENVEX_URL.encode("utf-8") + b"\0").hexdigest()
    body_file = client.cache_dir / f"{cache_key}.json"
    meta_file = client.cache_dir / f"{cache_key}.meta.json"
    body_file.write_text(json.dumps(sample_feed), encoding="utf-8")
    meta_file.write_text(json.dumps({"retrieved_at": "2026-08-11T17:52:27Z", "url": mod.OSERA_OPENVEX_URL}), encoding="utf-8")

    observed = datetime(2026, 11, 4, 2, 35, 0, tzinfo=timezone.utc)
    # 1. Exact package match + deduplication + preserved cache timestamp
    res_covered = mod.collect_osera_openvex(
        client,
        "maven",
        "org.apache.logging.log4j:log4j-core",
        observed,
        versions_in_use=[{"version": "2.12.4-osera.1"}, {"version": "2.14.1"}],
    )
    assert res_covered["coverage_status"] == "covered"
    assert res_covered["raw_statement_count"] == 2
    assert res_covered["deduplicated_statement_count"] == 1
    assert res_covered["published_patch_count"] == 1
    assert res_covered["patches"][0]["version"] == "2.12.4-osera.1"
    assert res_covered["patches"][0]["timestamp"] == "2026-11-02T15:22:11Z"
    assert res_covered["fixed_cves"] == ["CVE-2021-44228"]
    # Cached response preserves the original retrieval timestamp rather than synthesizing utc_now()
    assert res_covered["observed_at"] == "2026-08-11T17:52:27Z"
    assert res_covered["retrieved_at"] == "2026-08-11T17:52:27Z"
    claims = {c["version"]: c["matched_in_feed"] for c in res_covered["installed_version_claims"]}
    assert claims == {
        "2.12.4-osera.1": True,
        "2.14.1": False,
    }

    # 2. Uncovered package (jodd-json) reports no_published_osera_fix with 0 patches
    res_uncovered = mod.collect_osera_openvex(
        client,
        "maven",
        "org.jodd:jodd-json",
        observed,
    )
    assert res_uncovered["coverage_status"] == "no_published_osera_fix"
    assert res_uncovered["published_patch_count"] == 0
    assert res_uncovered["patches"] == []

    # 3. Unavailable/invalid OpenVEX feed handled gracefully
    bad_client = mod.HttpClient(tmp_path / "bad_cache", refresh=False)
    bad_body = bad_client.cache_dir / f"{cache_key}.json"
    bad_body.write_text(json.dumps({"unexpected": "shape"}), encoding="utf-8")
    res_unavailable = mod.collect_osera_openvex(
        bad_client,
        "maven",
        "org.apache.logging.log4j:log4j-core",
        observed,
    )
    assert res_unavailable["coverage_status"] == "unavailable"
    assert res_unavailable["confidence"] == 0.0
    assert res_unavailable["published_patch_count"] == 0


def _load_refresh_oss_risk_module():
    import importlib.util

    refresh_path = Path(__file__).resolve().parents[1] / "oss-risk" / "collectors" / "refresh_oss_risk.py"
    spec = importlib.util.spec_from_file_location("refresh_oss_risk", refresh_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_refresh_oss_risk_validate_only_passes_on_committed_datasets():
    mod = _load_refresh_oss_risk_module()
    assert mod.main(["--validate-only"]) == 0


def test_refresh_oss_risk_fail_closed_preserves_existing_published_files(tmp_path, monkeypatch):
    mod = _load_refresh_oss_risk_module()
    out_dir = tmp_path / "published"
    out_dir.mkdir(parents=True)
    stage_dir = tmp_path / "staging"

    # Seed existing valid baseline files in out_dir
    seed_record = {
        "project": {
            "name": "log4j-core",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "enterprise": {"versions_in_use": [{"version": "2.12.4-osera.1"}]},
        "evidence": {"finos_osera_backpatch": {"backpatch_repository": "finos-osera/backpatch-log4j2"}},
    }
    baseline_seeds = {"schema_version": "0.1", "records": [seed_record, {**seed_record, "project": {**seed_record["project"], "name": "jodd-json", "package": "org.jodd:jodd-json"}}]}
    baseline_bp = {"schema_version": "0.1", "generated_at": "2026-10-01T00:00:00Z", "records": [seed_record, seed_record]}
    seeds_file = out_dir / mod.DEFAULT_BACKPATCH_SEEDS.name
    bp_file = out_dir / mod.DEFAULT_BACKPATCH_SCORECARDS.name
    seeds_file.write_text(json.dumps(baseline_seeds), encoding="utf-8")
    bp_file.write_text(json.dumps(baseline_bp), encoding="utf-8")
    original_bp_text = bp_file.read_text(encoding="utf-8")

    # 1. Missing GitHub token fails closed before touching out_dir
    monkeypatch.setattr(mod.discovery, "github_token", lambda: "")
    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            skip_discovery=True,
            skip_examples=True,
            min_backpatch_records=1,
        )
        assert False, "Expected RuntimeError when GitHub token is missing"
    except RuntimeError as exc:
        assert "GitHub API authentication is required" in str(exc)
    assert bp_file.read_text(encoding="utf-8") == original_bp_text

    # 2. Shrink below existing published count fails closed
    monkeypatch.setattr(mod.discovery, "github_token", lambda: "ghs_test_token")
    shrunk_seeds = {"schema_version": "0.1", "records": [seed_record]}
    seeds_file.write_text(json.dumps(shrunk_seeds), encoding="utf-8")
    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            skip_discovery=True,
            skip_examples=True,
            min_backpatch_records=1,
        )
        assert False, "Expected RuntimeError when discovered seed count shrinks below baseline"
    except RuntimeError as exc:
        assert "smaller than existing published snapshot" in str(exc)
    assert bp_file.read_text(encoding="utf-8") == original_bp_text

    # 3. Unavailable OpenVEX or GitHub rate-limit error fails closed during staged validation
    def _bad_collect_record(_client, rec, _observed, include_osv=True):
        return {
            "project": rec["project"],
            "scores": {"oss_vitality": 72.5},
            "evidence": {
                "osera_openvex": {"coverage_status": "unavailable", "error": "HTTP 503"},
                "osv": {"source": "osv-query-api", "observed_at": "2026-11-04T00:00:00Z"},
                "cisa_kev": {"source": "cisa-kev-json", "observed_at": "2026-11-04T00:00:00Z", "catalog_count": 100},
                "github": {"source": "github-api", "observed_at": "2026-11-04T00:00:00Z", "repo_api": {"error": "HTTP 403"}},
            },
        }

    monkeypatch.setattr(mod.collector, "collect_record", _bad_collect_record)
    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            skip_discovery=True,
            skip_examples=True,
            allow_shrink=True,
            min_backpatch_records=1,
        )
        assert False, "Expected RuntimeError when staged validation fails"
    except RuntimeError as exc:
        msg = str(exc)
        assert "OSERA OpenVEX feed unavailable" in msg
        assert "GitHub API error" in msg
    assert bp_file.read_text(encoding="utf-8") == original_bp_text


def test_refresh_oss_risk_staged_publish_and_workflow_triggers(tmp_path, monkeypatch):
    mod = _load_refresh_oss_risk_module()
    out_dir = tmp_path / "published"
    out_dir.mkdir(parents=True)
    stage_dir = tmp_path / "staging"
    cache_dir = tmp_path / "cache"

    seed_record = {
        "project": {
            "name": "log4j-core",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "enterprise": {"versions_in_use": [{"version": "2.12.4-osera.1"}]},
        "evidence": {"finos_osera_backpatch": {"backpatch_repository": "finos-osera/backpatch-log4j2"}},
    }
    seeds_file = out_dir / mod.DEFAULT_BACKPATCH_SEEDS.name
    seeds_file.write_text(json.dumps({"schema_version": "0.1", "records": [seed_record]}), encoding="utf-8")
    ex_seeds_file = tmp_path / "example-seeds.json"
    ex_seeds_file.write_text(json.dumps({"records": [seed_record]}), encoding="utf-8")

    observed_refresh_flags = []

    def _valid_collect_record(client, rec, _observed, include_osv=True):
        observed_refresh_flags.append(client.refresh)
        return {
            "project": rec["project"],
            "scores": {"oss_vitality": 81.2},
            "evidence": {
                "osera_openvex": {
                    "coverage_status": "covered",
                    "retrieved_at": "2026-11-04T12:00:00Z",
                    "feed_version": 161,
                    "feed_last_updated": "2026-11-02T15:22:11Z",
                },
                "osv": {"source": "osv-query-api", "observed_at": "2026-11-04T12:00:00Z"},
                "cisa_kev": {
                    "source": "cisa-kev-json",
                    "observed_at": "2026-11-04T12:00:00Z",
                    "catalog_count": 1662,
                },
                "github": {
                    "source": "github-api",
                    "observed_at": "2026-11-04T12:00:00Z",
                    "confidence": 0.9,
                    "repo_api": {"status": 200},
                    "release_api": {"status": 200},
                    "commit_api": {"status": 200},
                    "issue_api": {"status": 200},
                    "pull_api": {"status": 200},
                },
            },
        }

    monkeypatch.setattr(mod.discovery, "github_token", lambda: "ghs_test_token")
    monkeypatch.setattr(mod.collector, "collect_record", _valid_collect_record)

    published = mod.run_refresh(
        staging_dir=stage_dir,
        output_dir=out_dir,
        cache_dir=cache_dir,
        example_seeds_path=ex_seeds_file,
        skip_discovery=True,
        skip_examples=False,
        min_backpatch_records=1,
        min_example_records=1,
    )
    assert observed_refresh_flags == [True, True]
    assert set(published.keys()) == {
        "finos-osera-backpatch-libraries.json",
        "finos-osera-backpatch-scorecards.json",
        "collected-library-scorecards.json",
    }

    root = Path(__file__).resolve().parents[1]
    refresh_wf = (root / ".github" / "workflows" / "refresh-oss-risk.yml").read_text(encoding="utf-8")
    pr_checks_wf = (root / ".github" / "workflows" / "pr-checks.yml").read_text(encoding="utf-8")
    pages_wf = (root / ".github" / "workflows" / "pages.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in refresh_wf
    assert "schedule:" in refresh_wf
    assert "npm run refresh:oss-risk" in refresh_wf
    assert "npm run validate:oss-risk" in refresh_wf
    assert '"oss-risk/**"' in pr_checks_wf
    assert '"oss-risk/**"' in pages_wf


def test_refresh_oss_risk_rejects_github_subrequest_and_multipage_failures(tmp_path, monkeypatch):
    mod = _load_refresh_oss_risk_module()
    out_dir = tmp_path / "published"
    out_dir.mkdir(parents=True)
    stage_dir = tmp_path / "staging"

    seed_record = {
        "project": {
            "name": "log4j-core",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "enterprise": {"versions_in_use": [{"version": "2.12.4-osera.1"}]},
        "evidence": {"finos_osera_backpatch": {"backpatch_repository": "finos-osera/backpatch-log4j2"}},
    }
    seeds_file = out_dir / mod.DEFAULT_BACKPATCH_SEEDS.name
    bp_file = out_dir / mod.DEFAULT_BACKPATCH_SCORECARDS.name
    seeds_file.write_text(json.dumps({"schema_version": "0.1", "records": [seed_record]}), encoding="utf-8")
    bp_file.write_text(json.dumps({"schema_version": "0.1", "generated_at": "2026-10-01T00:00:00Z", "records": [seed_record]}), encoding="utf-8")
    original_bp_text = bp_file.read_text(encoding="utf-8")

    # 1. Verify summarize_github_metas surfaces multi-page errors (e.g. page 1 succeeds, page 2 hits HTTP 403)
    page_summary = mod.collector.summarize_github_metas(
        [
            {"status": 200, "url": "https://api.github.com/repos/apache/logging-log4j2/commits?per_page=100&page=1"},
            {"error": "HTTP 403", "url": "https://api.github.com/repos/apache/logging-log4j2/commits?per_page=100&page=2"},
        ]
    )
    assert page_summary["error"] == "HTTP 403"
    assert page_summary["pages_fetched"] == 2
    assert len(page_summary["page_errors"]) == 1

    # 2. Verify committed scorecards fail validation if release_api, commit_api, issue_api, or pull_api is set to HTTP 403
    committed_bp = json.loads(mod.DEFAULT_BACKPATCH_SCORECARDS.read_text(encoding="utf-8"))
    for sub_key in ("release_api", "commit_api", "issue_api", "pull_api"):
        mutated = json.loads(json.dumps(committed_bp))
        for rec in mutated["records"]:
            gh = rec.get("evidence", {}).get("github")
            if isinstance(gh, dict):
                gh[sub_key] = {"error": "HTTP 403"}
        errs = mod.validate_scorecards_payload(
            mutated,
            min_records=mod.MIN_BACKPATCH_RECORDS,
            require_covered_openvex=True,
            label="finos-osera-backpatch-scorecards.json",
        )
        assert any(f"GitHub subrequest {sub_key} failed" in e for e in errs), f"Expected validation error for {sub_key}"

    # 3. Verify each GitHub subrequest field (release_api, tag_api, commit_api, issue_api, pull_api) is rejected on HTTP 403 during run_refresh even when repo_api succeeds
    monkeypatch.setattr(mod.discovery, "github_token", lambda: "ghs_test_token")
    for sub_key in ("release_api", "tag_api", "commit_api", "issue_api", "pull_api"):
        def _subrequest_fail_collect(_client, rec, _observed, include_osv=True, _failing_key=sub_key):
            gh = {
                "source": "github-api",
                "observed_at": "2026-11-04T12:00:00Z",
                "confidence": 0.9,
                "repo_api": {"status": 200},
                "release_api": {"status": 200},
                "commit_api": {"status": 200},
                "issue_api": {"status": 200},
                "pull_api": {"status": 200},
            }
            gh[_failing_key] = {"error": "HTTP 403", "url": f"https://api.github.com/repos/apache/logging-log4j2/{_failing_key}"}
            return {
                "project": rec["project"],
                "scores": {"oss_vitality": 80.0},
                "evidence": {
                    "osera_openvex": {"coverage_status": "covered", "retrieved_at": "2026-11-04T12:00:00Z", "feed_version": 161},
                    "osv": {"source": "osv-query-api", "observed_at": "2026-11-04T12:00:00Z"},
                    "cisa_kev": {"source": "cisa-kev-json", "observed_at": "2026-11-04T12:00:00Z", "catalog_count": 1662},
                    "github": gh,
                },
            }

        monkeypatch.setattr(mod.collector, "collect_record", _subrequest_fail_collect)
        try:
            mod.run_refresh(
                staging_dir=stage_dir,
                output_dir=out_dir,
                skip_discovery=True,
                skip_examples=True,
                min_backpatch_records=1,
            )
            assert False, f"Expected RuntimeError when {sub_key} fails with HTTP 403"
        except RuntimeError as exc:
            assert f"GitHub subrequest {sub_key} failed" in str(exc)
        assert bp_file.read_text(encoding="utf-8") == original_bp_text


def test_refresh_oss_risk_transactional_publish_rolls_back_entire_set_on_mid_write_failure(tmp_path, monkeypatch):
    mod = _load_refresh_oss_risk_module()
    out_dir = tmp_path / "published"
    out_dir.mkdir(parents=True)
    stage_dir = tmp_path / "staging"

    seed_record = {
        "project": {
            "name": "log4j-core",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
        },
        "enterprise": {"versions_in_use": [{"version": "2.12.4-osera.1"}]},
        "evidence": {"finos_osera_backpatch": {"backpatch_repository": "finos-osera/backpatch-log4j2"}},
    }
    seeds_file = out_dir / mod.DEFAULT_BACKPATCH_SEEDS.name
    bp_file = out_dir / mod.DEFAULT_BACKPATCH_SCORECARDS.name
    ex_file = out_dir / mod.DEFAULT_EXAMPLE_SCORECARDS.name
    ex_seeds_file = tmp_path / "example-seeds.json"
    ex_seeds_file.write_text(json.dumps({"records": [seed_record]}), encoding="utf-8")

    # Write distinct baseline content to all 3 published files
    seeds_file.write_text(json.dumps({"schema_version": "0.1", "baseline": "old-seeds", "records": [seed_record]}), encoding="utf-8")
    bp_file.write_text(json.dumps({"schema_version": "0.1", "baseline": "old-bp", "generated_at": "2026-10-01T00:00:00Z", "records": [seed_record]}), encoding="utf-8")
    ex_file.write_text(json.dumps({"schema_version": "0.1", "baseline": "old-ex", "generated_at": "2026-10-01T00:00:00Z", "records": [seed_record]}), encoding="utf-8")

    old_seeds_bytes = seeds_file.read_bytes()
    old_bp_bytes = bp_file.read_bytes()
    old_ex_bytes = ex_file.read_bytes()

    def _new_collect_record(_client, rec, _observed, include_osv=True):
        return {
            "project": rec["project"],
            "scores": {"oss_vitality": 91.5},
            "evidence": {
                "osera_openvex": {"coverage_status": "covered", "retrieved_at": "2026-11-05T00:00:00Z", "feed_version": 162},
                "osv": {"source": "osv-query-api", "observed_at": "2026-11-05T00:00:00Z"},
                "cisa_kev": {"source": "cisa-kev-json", "observed_at": "2026-11-05T00:00:00Z", "catalog_count": 1662},
                "github": {
                    "source": "github-api",
                    "observed_at": "2026-11-05T00:00:00Z",
                    "confidence": 0.9,
                    "repo_api": {"status": 200},
                    "release_api": {"status": 200},
                    "commit_api": {"status": 200},
                    "issue_api": {"status": 200},
                    "pull_api": {"status": 200},
                },
            },
        }

    # Ensure staged seeds differ from old_seeds_bytes so we can prove rollback of the 1st file after it was already replaced
    monkeypatch.setattr(mod.discovery, "github_token", lambda: "ghs_test_token")
    monkeypatch.setattr(mod.discovery.GitHubClient, "get", lambda self, path: [])
    monkeypatch.setattr(mod.discovery, "list_org_repos", lambda client, org: [{"name": "backpatch-log4j2", "full_name": "finos-osera/backpatch-log4j2"}])
    monkeypatch.setattr(mod.discovery, "make_record", lambda client, repo, observed_at: seed_record)
    monkeypatch.setattr(mod.collector, "collect_record", _new_collect_record)

    real_commit = mod._commit_staged_file
    commit_calls = []

    def _fail_on_second_commit(tmp_path: Path, dst: Path) -> None:
        commit_calls.append(dst.name)
        if len(commit_calls) == 2:
            raise OSError("Simulated disk failure after first file was already replaced")
        real_commit(tmp_path, dst)

    monkeypatch.setattr(mod, "_commit_staged_file", _fail_on_second_commit)

    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            example_seeds_path=ex_seeds_file,
            skip_discovery=False,
            skip_examples=False,
            min_backpatch_records=1,
            min_example_records=1,
        )
        assert False, "Expected OSError during mid-publication commit"
    except OSError as exc:
        assert "Simulated disk failure after first file was already replaced" in str(exc)

    # First file was committed before the second failed, and must be rolled back to its exact old bytes
    assert len(commit_calls) == 2
    assert seeds_file.read_bytes() == old_seeds_bytes
    assert bp_file.read_bytes() == old_bp_bytes
    assert ex_file.read_bytes() == old_ex_bytes
    assert list(out_dir.glob(".*.tmp.*")) == []
    assert list(out_dir.glob(".*.bak.*")) == []


def test_refresh_oss_risk_rejects_oversized_seed_payload_and_preserves_existing_outputs(tmp_path, monkeypatch):
    mod = _load_refresh_oss_risk_module()
    out_dir = tmp_path / "published"
    out_dir.mkdir(parents=True)
    stage_dir = tmp_path / "staging"

    seed_record = {
        "project": {
            "name": "log4j-core",
            "ecosystem": "maven",
            "package": "org.apache.logging.log4j:log4j-core",
            "repository": "https://github.com/apache/logging-log4j2",
            "padding": "x" * 2048,
        },
        "enterprise": {"versions_in_use": [{"version": "2.12.4-osera.1"}]},
        "evidence": {"finos_osera_backpatch": {"backpatch_repository": "finos-osera/backpatch-log4j2"}},
    }
    seeds_file = out_dir / mod.DEFAULT_BACKPATCH_SEEDS.name
    bp_file = out_dir / mod.DEFAULT_BACKPATCH_SCORECARDS.name
    seeds_file.write_text(json.dumps({"schema_version": "0.1", "records": [seed_record]}), encoding="utf-8")
    bp_file.write_text(json.dumps({"schema_version": "0.1", "generated_at": "2026-10-01T00:00:00Z", "records": [seed_record]}), encoding="utf-8")
    original_seeds_bytes = seeds_file.read_bytes()
    original_bp_bytes = bp_file.read_bytes()

    # Enforce a 512-byte distribution cap so the ~2.3 KiB seed file is rejected
    monkeypatch.setattr(mod, "MAX_DATASET_BYTES", 512)
    monkeypatch.setattr(
        mod,
        "check_file_size",
        lambda path, max_bytes=512: f"{path.name}: file size {path.stat().st_size:,} bytes exceeds limit {max_bytes:,} bytes"
        if path.stat().st_size > max_bytes
        else None,
    )
    monkeypatch.setattr(mod.discovery, "github_token", lambda: "ghs_test_token")
    monkeypatch.setattr(mod.discovery.GitHubClient, "get", lambda self, path: [])
    monkeypatch.setattr(mod.discovery, "list_org_repos", lambda client, org: [{"name": "backpatch-log4j2", "full_name": "finos-osera/backpatch-log4j2"}])
    monkeypatch.setattr(mod.discovery, "make_record", lambda client, repo, observed_at: seed_record)

    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            skip_discovery=False,
            skip_examples=True,
            min_backpatch_records=1,
        )
        assert False, "Expected RuntimeError when staged seed file exceeds distribution size limit"
    except RuntimeError as exc:
        assert "finos-osera-backpatch-libraries.json: file size" in str(exc)
        assert "exceeds limit" in str(exc)

    assert seeds_file.read_bytes() == original_seeds_bytes
    assert bp_file.read_bytes() == original_bp_bytes

    # Verify --require-live-discovery fails closed when /orgs/finos-osera/repos returns 0 visible backpatch-* repos
    monkeypatch.setattr(mod, "check_file_size", lambda path, max_bytes=mod.MAX_DATASET_BYTES: None)
    monkeypatch.setattr(mod.discovery, "list_org_repos", lambda client, org: [{"name": "risk-navigator"}])
    try:
        mod.run_refresh(
            staging_dir=stage_dir,
            output_dir=out_dir,
            skip_discovery=False,
            require_live_discovery=True,
            skip_examples=True,
            min_backpatch_records=1,
        )
        assert False, "Expected RuntimeError when require_live_discovery=True and 0 backpatch-* repos are visible"
    except RuntimeError as exc:
        assert "expected at least 1 seed records, found 0" in str(exc)
    assert seeds_file.read_bytes() == original_seeds_bytes
    assert bp_file.read_bytes() == original_bp_bytes





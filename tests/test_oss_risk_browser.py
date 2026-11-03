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
    assert "Vulnerability Intelligence" in docs_mdx
    assert "derived from OSV CVE aliases" in docs_mdx

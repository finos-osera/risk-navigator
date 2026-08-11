#!/usr/bin/env python3
"""Collect live OSS scorecard evidence for library risk records."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "oss-risk" / "examples" / "library-scorecards.json"
DEFAULT_OUTPUT = ROOT / "oss-risk" / "data" / "collected-library-scorecards.json"
DEFAULT_CACHE = ROOT / "oss-risk" / "data" / "cache"

SCORECARD_API = "https://api.scorecard.dev/projects"
DEPSDEV_API = "https://api.deps.dev/v3"
DEPSDEV_ALPHA_API = "https://api.deps.dev/v3alpha"
OSV_API = "https://api.osv.dev/v1/query"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-month"

DIMENSION_WEIGHTS = {
    "project_vitality": 0.25,
    "security_health": 0.25,
    "sustainability_governance": 0.20,
    "dependency_hygiene": 0.15,
    "ecosystem_resilience": 0.15,
}

DEPSDEV_SYSTEMS = {
    "npm": "NPM",
    "pypi": "PYPI",
    "maven": "MAVEN",
    "cargo": "CARGO",
    "gem": "RUBYGEMS",
    "rubygems": "RUBYGEMS",
    "nuget": "NUGET",
    "go": "GO",
}

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "go": "Go",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "almalinux": "AlmaLinux",
    "rocky": "Rocky Linux",
    "rocky linux": "Rocky Linux",
}

SECURITY_CHECKS = {
    "Binary-Artifacts",
    "Branch-Protection",
    "Code-Review",
    "Dangerous-Workflow",
    "Dependency-Update-Tool",
    "Fuzzing",
    "Maintained",
    "Packaging",
    "Pinned-Dependencies",
    "SAST",
    "Security-Policy",
    "Signed-Releases",
    "Token-Permissions",
    "Vulnerabilities",
}

GOVERNANCE_CHECKS = {
    "CII-Best-Practices",
    "Code-Review",
    "Contributors",
    "License",
    "Maintained",
    "Security-Policy",
}

DEPENDENCY_CHECKS = {
    "Dependency-Update-Tool",
    "Pinned-Dependencies",
    "Vulnerabilities",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_since(value: str, observed: datetime) -> Optional[int]:
    parsed = parse_iso(value)
    if not parsed:
        return None
    return max(0, (observed - parsed).days)


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_log(value: float, target: float) -> float:
    if value <= 0:
        return 0.0
    return clamp(math.log1p(value) / math.log1p(target) * 100)


def repo_path(repository_url: str) -> Optional[str]:
    parsed = urlparse(repository_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


class HttpClient:
    def __init__(self, cache_dir: Path, refresh: bool = False, timeout: float = 30.0):
        self.cache_dir = cache_dir
        self.refresh = refresh
        self.timeout = timeout
        self.github_token = self._github_token()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _github_token(self) -> str:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            return token
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return ""
        return result.stdout.strip()

    def json(self, url: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        payload = json.dumps(body, sort_keys=True).encode("utf-8") if body is not None else b""
        cache_key = hashlib.sha256(method.encode("utf-8") + b"\0" + url.encode("utf-8") + b"\0" + payload).hexdigest()
        cache_path = self.cache_dir / f"{cache_key}.json"
        if cache_path.exists() and not self.refresh:
            return json.loads(cache_path.read_text(encoding="utf-8")), {"cache": "hit", "url": url}

        headers = {
            "Accept": "application/json",
            "User-Agent": "osera-oss-risk-collector/0.1",
        }
        if self.github_token and "api.github.com" in url:
            headers["Authorization"] = f"Bearer {self.github_token}"
        if body is not None:
            headers["Content-Type"] = "application/json"

        req = Request(url, data=payload if body is not None else None, headers=headers, method=method)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                cache_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                return data, {"cache": "miss", "url": url, "status": resp.status}
        except HTTPError as exc:
            error = {
                "error": f"HTTP {exc.code}",
                "url": url,
                "body": exc.read().decode("utf-8", errors="replace")[:500],
            }
            return {}, error
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            return {}, {"error": str(exc), "url": url}


def read_records(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return payload["records"]
    if isinstance(payload, list):
        return payload
    raise ValueError("Input must be a JSON array or an object with records[]")


def github_get(client: HttpClient, path: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    return client.json(f"https://api.github.com{path}")


def github_list(client: HttpClient, path: str, max_pages: int = 5) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    metas: List[Dict[str, Any]] = []
    sep = "&" if "?" in path else "?"
    for page in range(1, max_pages + 1):
        data, meta = github_get(client, f"{path}{sep}per_page=100&page={page}")
        metas.append(meta)
        if not isinstance(data, list):
            break
        rows.extend(data)
        if len(data) < 100:
            break
    return rows, metas


def collect_github(client: HttpClient, repository_url: str, observed: datetime) -> Dict[str, Any]:
    path = repo_path(repository_url)
    if not path:
        return {"source": "github-api", "confidence": 0.0, "error": "not a github.com repository"}

    repo, repo_meta = github_get(client, f"/repos/{path}")
    releases, release_metas = github_list(client, f"/repos/{path}/releases", max_pages=1)
    tags, _ = github_list(client, f"/repos/{path}/tags", max_pages=1) if not releases else ([], [])
    commits, commit_metas = github_list(
        client,
        f"/repos/{path}/commits?since={observed.replace(year=observed.year - 1).isoformat().replace('+00:00', 'Z')}",
        max_pages=10,
    )
    issues, issue_metas = github_list(
        client,
        f"/repos/{path}/issues?state=all&since={observed.replace(year=observed.year - 1).isoformat().replace('+00:00', 'Z')}",
        max_pages=3,
    )
    pulls, pull_metas = github_list(client, f"/repos/{path}/pulls?state=closed", max_pages=3)

    author_windows = {"365d": set(), "180d": set(), "90d": set(), "30d": set()}
    commit_windows = {"365d": 0, "180d": 0, "90d": 0, "30d": 0}
    for commit in commits:
        date = (((commit.get("commit") or {}).get("author") or {}).get("date") or "")
        age = days_since(date, observed)
        if age is None:
            continue
        login = ((commit.get("author") or {}).get("login")) or (((commit.get("commit") or {}).get("author") or {}).get("email")) or "unknown"
        for label, window in (("365d", 365), ("180d", 180), ("90d", 90), ("30d", 30)):
            if age <= window:
                commit_windows[label] += 1
                author_windows[label].add(login)

    latest_release = releases[0] if releases else {}
    latest_tag = tags[0] if tags else {}
    latest_release_at = latest_release.get("published_at") or latest_release.get("created_at") or ""
    issue_rows = [issue for issue in issues if not issue.get("pull_request")]
    issues_opened_365d = len(issue_rows)
    issues_closed_365d = sum(1 for issue in issue_rows if issue.get("closed_at"))
    issue_closure_ratio_365d = round(issues_closed_365d / issues_opened_365d, 3) if issues_opened_365d else None

    merge_latencies = []
    merged_prs = 0
    closed_prs = 0
    for pull in pulls:
        closed_prs += 1
        merged_at = pull.get("merged_at")
        created_at = pull.get("created_at")
        if not merged_at or not created_at:
            continue
        created = parse_iso(created_at)
        merged = parse_iso(merged_at)
        if not created or not merged:
            continue
        merged_prs += 1
        merge_latencies.append(max(0.0, (merged - created).total_seconds() / 86400))
    median_pr_merge_days = round(statistics.median(merge_latencies), 2) if merge_latencies else None
    pr_merge_ratio = round(merged_prs / closed_prs, 3) if closed_prs else None

    return {
        "source": "github-api",
        "url": f"https://api.github.com/repos/{path}",
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.9 if repo else 0.3,
        "stars": repo.get("stargazers_count"),
        "forks": repo.get("forks_count"),
        "open_issues": repo.get("open_issues_count"),
        "created_at": repo.get("created_at"),
        "pushed_at": repo.get("pushed_at"),
        "default_branch": repo.get("default_branch"),
        "latest_release": latest_release.get("tag_name") or latest_tag.get("name") or "",
        "latest_release_at": latest_release_at,
        "commits_365d": commit_windows["365d"],
        "commits_180d": commit_windows["180d"],
        "commits_90d": commit_windows["90d"],
        "commits_30d": commit_windows["30d"],
        "active_contributors_365d": len(author_windows["365d"]),
        "active_contributors_180d": len(author_windows["180d"]),
        "active_contributors_90d": len(author_windows["90d"]),
        "active_contributors_30d": len(author_windows["30d"]),
        "issues_opened_365d": issues_opened_365d,
        "issues_closed_365d": issues_closed_365d,
        "issue_closure_ratio_365d": issue_closure_ratio_365d,
        "closed_pr_sample": closed_prs,
        "merged_pr_sample": merged_prs,
        "pr_merge_ratio": pr_merge_ratio,
        "median_pr_merge_days": median_pr_merge_days,
        "commit_sample_truncated": len(commits) >= 1000,
        "repo_api": repo_meta,
        "release_api": release_metas[0] if release_metas else {},
        "commit_api": commit_metas[0] if commit_metas else {},
        "issue_api": issue_metas[0] if issue_metas else {},
        "pull_api": pull_metas[0] if pull_metas else {},
    }


def collect_scorecard(client: HttpClient, repository_url: str, observed: datetime) -> Dict[str, Any]:
    path = repo_path(repository_url)
    if not path:
        return {"source": "openssf-scorecard-api", "confidence": 0.0, "error": "not a github.com repository"}
    project = f"github.com/{path}"
    data, meta = client.json(f"{SCORECARD_API}/{quote(project, safe='/')}")
    checks = data.get("checks") if isinstance(data, dict) else None
    simplified_checks = []
    if isinstance(checks, list):
        simplified_checks = [
            {
                "name": check.get("name"),
                "score": check.get("score"),
                "reason": check.get("reason"),
                "documentation_url": ((check.get("documentation") or {}).get("url")),
            }
            for check in checks
        ]
    return {
        "source": "openssf-scorecard-api",
        "url": f"{SCORECARD_API}/{project}",
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.95 if data.get("score") is not None else 0.2,
        "score": data.get("score"),
        "scorecard_version": ((data.get("scorecard") or {}).get("version")),
        "scorecard_date": data.get("date"),
        "checks": simplified_checks,
        "api": meta,
    }


def latest_version(versions: List[Dict[str, Any]]) -> Dict[str, Any]:
    default = [v for v in versions if v.get("isDefault")]
    if default:
        return default[0]
    dated = [v for v in versions if v.get("publishedAt")]
    if dated:
        return sorted(dated, key=lambda row: row.get("publishedAt") or "", reverse=True)[0]
    return versions[-1] if versions else {}


def collect_depsdev(client: HttpClient, ecosystem: str, package: str, observed: datetime) -> Dict[str, Any]:
    system = DEPSDEV_SYSTEMS.get(ecosystem.lower())
    if not system:
        return {
            "source": "not-applicable",
            "confidence": 0.0,
            "note": f"No deps.dev package query is configured for ecosystem: {ecosystem}",
        }
    encoded_package = quote(package, safe="")
    data, meta = client.json(f"{DEPSDEV_API}/systems/{system}/packages/{encoded_package}")
    versions = data.get("versions") if isinstance(data, dict) else []
    version_count = len(versions) if isinstance(versions, list) else 0
    latest = latest_version(versions if isinstance(versions, list) else [])
    version_key = latest.get("versionKey") or {}
    latest_name = version_key.get("name") or package
    latest_value = version_key.get("version") or ""
    latest_published_at = latest.get("publishedAt") or ""
    deprecated_count = sum(1 for version in versions if version.get("isDeprecated")) if isinstance(versions, list) else 0

    dependents: Dict[str, Any] = {}
    dependents_meta: Dict[str, Any] = {}
    if latest_value:
        dependents, dependents_meta = client.json(
            f"{DEPSDEV_ALPHA_API}/systems/{system}/packages/{quote(latest_name, safe='')}/versions/{quote(latest_value, safe='')}:dependents"
        )

    return {
        "source": "deps.dev-api",
        "url": f"{DEPSDEV_API}/systems/{system}/packages/{encoded_package}",
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.9 if version_count else 0.25,
        "system": system,
        "version_count": version_count,
        "latest_version": latest_value,
        "latest_published_at": latest_published_at,
        "latest_is_default": latest.get("isDefault"),
        "deprecated_version_count": deprecated_count,
        "dependent_count": dependents.get("dependentCount"),
        "direct_dependent_count": dependents.get("directDependentCount"),
        "indirect_dependent_count": dependents.get("indirectDependentCount"),
        "package_api": meta,
        "dependents_api": dependents_meta,
    }


def collect_npm_downloads(client: HttpClient, ecosystem: str, package: str, observed: datetime) -> Dict[str, Any]:
    if ecosystem.lower() != "npm":
        return {}
    data, meta = client.json(f"{NPM_DOWNLOADS_URL}/{quote(package, safe='')}")
    return {
        "source": "npm-downloads-api",
        "url": f"{NPM_DOWNLOADS_URL}/{package}",
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.85 if data.get("downloads") is not None else 0.2,
        "monthly_downloads": data.get("downloads"),
        "start": data.get("start"),
        "end": data.get("end"),
        "api": meta,
    }


def collect_osv(client: HttpClient, ecosystem: str, package: str, observed: datetime) -> Dict[str, Any]:
    osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem.lower())
    if not osv_ecosystem:
        return {
            "source": "not-applicable",
            "confidence": 0.0,
            "note": f"No OSV package query is configured for ecosystem: {ecosystem}",
        }
    body = {"package": {"ecosystem": osv_ecosystem, "name": package}}
    data, meta = client.json(OSV_API, method="POST", body=body)
    vulns = data.get("vulns") if isinstance(data, dict) else []
    cves: List[str] = []
    vuln_rows = []
    for vuln in vulns if isinstance(vulns, list) else []:
        aliases = [alias for alias in vuln.get("aliases", []) if isinstance(alias, str)]
        cves.extend(alias for alias in aliases if alias.startswith("CVE-"))
        vuln_rows.append(
            {
                "id": vuln.get("id"),
                "summary": vuln.get("summary"),
                "aliases": aliases,
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
            }
        )
    return {
        "source": "osv-query-api",
        "url": OSV_API,
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.9 if isinstance(vulns, list) else 0.2,
        "query": body,
        "vulnerability_count": len(vuln_rows),
        "cve_count": len(set(cves)),
        "cves": sorted(set(cves)),
        "vulnerabilities": vuln_rows,
        "api": meta,
    }


def collect_cisa_kev(client: HttpClient, cves: Iterable[str], observed: datetime) -> Dict[str, Any]:
    data, meta = client.json(CISA_KEV_URL)
    target = set(cves)
    rows = []
    for row in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
        cve = row.get("cveID")
        if cve in target:
            rows.append(
                {
                    "cveID": cve,
                    "vendorProject": row.get("vendorProject"),
                    "product": row.get("product"),
                    "dateAdded": row.get("dateAdded"),
                    "knownRansomwareCampaignUse": row.get("knownRansomwareCampaignUse"),
                    "shortDescription": row.get("shortDescription"),
                }
            )
    return {
        "source": "cisa-kev-json",
        "url": CISA_KEV_URL,
        "observed_at": observed.isoformat().replace("+00:00", "Z"),
        "confidence": 0.95 if data.get("vulnerabilities") else 0.2,
        "catalog_count": len(data.get("vulnerabilities", [])) if isinstance(data, dict) else 0,
        "matched_count": len(rows),
        "matched_cves": [row["cveID"] for row in rows],
        "matches": rows,
        "api": meta,
    }


def check_score(scorecard: Dict[str, Any], names: Iterable[str]) -> Optional[float]:
    wanted = set(names)
    scores = []
    for check in scorecard.get("checks", []) or []:
        if check.get("name") in wanted:
            value = check.get("score")
            if isinstance(value, (int, float)) and value >= 0:
                scores.append(value * 10)
    if not scores:
        return None
    return sum(scores) / len(scores)


def score_vitality(github: Dict[str, Any], scorecard: Dict[str, Any], observed: datetime) -> float:
    contributors = score_log(github.get("active_contributors_365d") or 0, 30)
    commits = score_log(github.get("commits_365d") or 0, 500)
    pushed_age = days_since(github.get("pushed_at") or "", observed)
    pushed = 0 if pushed_age is None else clamp(100 - pushed_age / 3)
    release_age = days_since(github.get("latest_release_at") or "", observed)
    release = 55 if release_age is None else clamp(100 - release_age / 10)
    closure_ratio = github.get("issue_closure_ratio_365d")
    issue_health = 60 if closure_ratio is None else clamp(float(closure_ratio) * 100)
    merge_days = github.get("median_pr_merge_days")
    pr_health = 60 if merge_days is None else clamp(100 - float(merge_days) * 3)
    maintained = check_score(scorecard, ["Maintained"])
    parts = [contributors * 0.20, commits * 0.15, pushed * 0.15, release * 0.20, issue_health * 0.10, pr_health * 0.10]
    parts.append((maintained if maintained is not None else 60) * 0.15)
    return round(clamp(sum(parts)), 1)


def score_security(scorecard: Dict[str, Any], osv: Dict[str, Any], kev: Dict[str, Any]) -> float:
    base = check_score(scorecard, SECURITY_CHECKS)
    if base is None and isinstance(scorecard.get("score"), (int, float)):
        base = float(scorecard["score"]) * 10
    if base is None:
        base = 55
    vuln_penalty = min(20, math.log1p(osv.get("vulnerability_count") or 0) * 4)
    kev_penalty = min(30, (kev.get("matched_count") or 0) * 12)
    return round(clamp(base - vuln_penalty - kev_penalty), 1)


def score_governance(scorecard: Dict[str, Any], github: Dict[str, Any]) -> float:
    base = check_score(scorecard, GOVERNANCE_CHECKS)
    if base is None:
        base = 55
    contributor_bonus = min(10, (github.get("active_contributors_365d") or 0) / 4)
    return round(clamp(base * 0.9 + contributor_bonus), 1)


def score_dependency_hygiene(scorecard: Dict[str, Any], depsdev: Dict[str, Any], observed: datetime) -> float:
    dep_checks = check_score(scorecard, DEPENDENCY_CHECKS)
    dep_checks = dep_checks if dep_checks is not None else 55
    age = days_since(depsdev.get("latest_published_at") or "", observed)
    recency = 50 if age is None else clamp(100 - age / 12)
    deprecated_count = depsdev.get("deprecated_version_count") or 0
    deprecated_penalty = min(20, math.log1p(deprecated_count) * 4)
    return round(clamp(dep_checks * 0.55 + recency * 0.45 - deprecated_penalty), 1)


def score_ecosystem_resilience(github: Dict[str, Any], depsdev: Dict[str, Any], npm: Dict[str, Any], observed: datetime) -> float:
    stars = score_log(github.get("stars") or 0, 50000)
    forks = score_log(github.get("forks") or 0, 8000)
    dependents = score_log(depsdev.get("dependent_count") or 0, 20000)
    downloads = score_log(npm.get("monthly_downloads") or 0, 500000000)
    created_age = days_since(github.get("created_at") or "", observed)
    age_score = 40 if created_age is None else clamp(created_age / 365 / 10 * 100)
    if npm:
        return round(clamp(stars * 0.25 + forks * 0.15 + dependents * 0.25 + downloads * 0.20 + age_score * 0.15), 1)
    return round(clamp(stars * 0.30 + forks * 0.20 + dependents * 0.30 + age_score * 0.20), 1)


def ecosystem_criticality(github: Dict[str, Any], depsdev: Dict[str, Any], npm: Dict[str, Any], enterprise: Dict[str, Any]) -> float:
    stars = score_log(github.get("stars") or 0, 50000)
    dependents = score_log(depsdev.get("dependent_count") or 0, 20000)
    downloads = score_log(npm.get("monthly_downloads") or 0, 500000000)
    apps = score_log(enterprise.get("application_count") or 0, 1000)
    if npm:
        value = stars * 0.2 + dependents * 0.3 + downloads * 0.25 + apps * 0.25
    else:
        value = stars * 0.25 + dependents * 0.35 + apps * 0.40
    return round(clamp(value), 1)


def calculate_oss_vitality(scores: Dict[str, Any]) -> float:
    total = 0.0
    for key, weight in DIMENSION_WEIGHTS.items():
        total += clamp(scores.get(key) or 0) * weight
    return round(clamp(total), 1)


def exposure_factor(enterprise: Dict[str, Any]) -> float:
    app_count = int(enterprise.get("application_count") or 0)
    direct_count = int(enterprise.get("direct_dependency_count") or 0)
    tier1_count = int(enterprise.get("tier1_application_count") or 0)
    internet_count = int(enterprise.get("internet_facing_application_count") or 0)
    regulated_count = int(enterprise.get("regulated_application_count") or 0)
    base = min(1.0, math.log1p(app_count) / math.log(1001))
    direct = min(0.25, direct_count / max(app_count, 1) * 0.25)
    business = min(0.35, (tier1_count * 0.08) + (internet_count * 0.03) + (regulated_count * 0.04))
    return 0.5 + min(0.5, base * 0.35 + direct + business)


def version_risk_factor(enterprise: Dict[str, Any]) -> float:
    versions = max(1, len(enterprise.get("versions_in_use") or []))
    unsupported = int(enterprise.get("unsupported_version_count") or 0)
    vulnerable = int(enterprise.get("known_vulnerable_version_count") or 0)
    return 0.75 + min(0.45, (unsupported / versions * 0.2) + (vulnerable / versions * 0.25))


def enterprise_priority(scores: Dict[str, Any], enterprise: Dict[str, Any]) -> float:
    vitality = scores["oss_vitality"]
    criticality = clamp(scores.get("ecosystem_criticality") or 0) / 100
    confidence = float(scores.get("confidence") or 0.7)
    confidence_factor = 0.85 + min(0.15, max(0.0, confidence) * 0.15)
    raw = (
        (100 - vitality)
        * (0.65 + 0.7 * criticality)
        * exposure_factor(enterprise)
        * version_risk_factor(enterprise)
        * confidence_factor
    )
    return round(clamp(raw), 1)


def undermaintenance_pressure(github: Dict[str, Any], depsdev: Dict[str, Any], npm: Dict[str, Any], enterprise: Dict[str, Any]) -> float:
    downstream = (depsdev.get("dependent_count") or 0) + math.sqrt(npm.get("monthly_downloads") or 0) + (enterprise.get("application_count") or 0) * 10
    capacity = (github.get("active_contributors_365d") or 0) + (github.get("active_contributors_90d") or 0)
    if downstream <= 0:
        return 0.0
    return round(math.log1p(downstream) / math.log(2 + max(capacity, 0)), 2)


def confidence(*sources: Dict[str, Any]) -> float:
    values = [float(source.get("confidence") or 0) for source in sources if source]
    if not values:
        return 0.2
    return round(sum(values) / len(values), 2)


def collect_record(client: HttpClient, record: Dict[str, Any], observed: datetime, include_osv: bool) -> Dict[str, Any]:
    project = record.get("project", {})
    enterprise = dict(record.get("enterprise", {}))
    github = collect_github(client, project.get("repository", ""), observed)
    scorecard = collect_scorecard(client, project.get("repository", ""), observed)
    depsdev = collect_depsdev(client, project.get("ecosystem", ""), project.get("package", ""), observed)
    npm = collect_npm_downloads(client, project.get("ecosystem", ""), project.get("package", ""), observed)
    osv = collect_osv(client, project.get("ecosystem", ""), project.get("package", ""), observed) if include_osv else {}
    kev = collect_cisa_kev(client, osv.get("cves") or [], observed) if include_osv else {}
    registry_confidence = max(depsdev.get("confidence", 0), npm.get("confidence", 0) if npm else 0)
    registry_source = "combined-registry-evidence"
    if depsdev.get("source") == "not-applicable" and not npm:
        registry_source = "not-applicable"

    known_vulnerable_versions = enterprise.get("known_vulnerable_version_count") or 0
    if include_osv and osv.get("vulnerability_count") and not known_vulnerable_versions:
        # Package-level OSV queries are historical/all-version evidence, not proof
        # that the enterprise's deployed version is affected.
        enterprise["known_vulnerable_version_count"] = known_vulnerable_versions

    scores = {
        "project_vitality": score_vitality(github, scorecard, observed),
        "security_health": score_security(scorecard, osv, kev),
        "sustainability_governance": score_governance(scorecard, github),
        "dependency_hygiene": score_dependency_hygiene(scorecard, depsdev, observed),
        "ecosystem_resilience": score_ecosystem_resilience(github, depsdev, npm, observed),
        "ecosystem_criticality": ecosystem_criticality(github, depsdev, npm, enterprise),
        "confidence": confidence(github, scorecard, depsdev, osv if include_osv else {}),
    }
    scores["oss_vitality"] = calculate_oss_vitality(scores)
    scores["enterprise_priority_risk"] = enterprise_priority(scores, enterprise)
    scores["undermaintenance_pressure"] = undermaintenance_pressure(github, depsdev, npm, enterprise)

    evidence = dict(record.get("evidence", {}))
    evidence.update({
        "openssf_scorecard": scorecard,
        "openssf_criticality": {
            "source": "not-collected",
            "confidence": 0.0,
            "note": "No stable per-project Criticality Score endpoint is used by this v0 collector. ecosystem_criticality is a local proxy from repository, registry, and enterprise exposure.",
        },
        "chaoss_derived": {
            "source": "github-api-derived",
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "confidence": github.get("confidence", 0) * 0.85,
            "active_contributors_365d": github.get("active_contributors_365d"),
            "active_contributors_180d": github.get("active_contributors_180d"),
            "active_contributors_90d": github.get("active_contributors_90d"),
            "active_contributors_30d": github.get("active_contributors_30d"),
            "commits_365d": github.get("commits_365d"),
            "commits_180d": github.get("commits_180d"),
            "commits_90d": github.get("commits_90d"),
            "commits_30d": github.get("commits_30d"),
            "issues_opened_365d": github.get("issues_opened_365d"),
            "issues_closed_365d": github.get("issues_closed_365d"),
            "issue_closure_ratio_365d": github.get("issue_closure_ratio_365d"),
            "closed_pr_sample": github.get("closed_pr_sample"),
            "merged_pr_sample": github.get("merged_pr_sample"),
            "pr_merge_ratio": github.get("pr_merge_ratio"),
            "median_pr_merge_days": github.get("median_pr_merge_days"),
            "commit_sample_truncated": github.get("commit_sample_truncated"),
        },
        "osv": osv or {"source": "disabled", "confidence": 0.0},
        "cisa_kev": kev or {"source": "disabled", "confidence": 0.0},
        "github": github,
        "package_registry": {
            "source": registry_source,
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "confidence": registry_confidence,
            **{k: v for k, v in depsdev.items() if k not in {"source", "observed_at", "confidence"}},
            **({"npm_monthly_downloads": npm.get("monthly_downloads"), "npm_download_window": f"{npm.get('start')}..{npm.get('end')}"} if npm else {}),
        },
    })

    return {
        "schema_version": "0.1",
        "project": project,
        "scores": scores,
        "evidence": evidence,
        "enterprise": enterprise,
        "notes": [
            "Collected from live public APIs. Dimension scores are v0 heuristics; inspect evidence and confidence before using for decisions.",
            "Package-level OSV queries report known vulnerabilities for any affected version, not proof that every deployed version is currently vulnerable.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect live OSS library risk evidence.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="Input seed records JSON")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output collected records JSON")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE, help="HTTP cache directory")
    parser.add_argument("--refresh", action="store_true", help="Ignore cached API responses")
    parser.add_argument("--no-osv", action="store_true", help="Skip OSV package queries and CISA KEV matching")
    args = parser.parse_args()

    observed = datetime.now(timezone.utc).replace(microsecond=0)
    client = HttpClient(args.cache_dir, refresh=args.refresh)
    records = read_records(args.input)
    collected = [collect_record(client, record, observed, include_osv=not args.no_osv) for record in records]
    payload = {
        "schema_version": "0.1",
        "generated_at": observed.isoformat().replace("+00:00", "Z"),
        "methodology": "Live public API evidence collection plus v0 deterministic scoring heuristics.",
        "records": collected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(collected)} records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Create org raw CSV extracts for Risk Navigator.

Supports:
- Synthetic FINOS-like portfolio (default)
- CycloneDX SBOM directory import (optional)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

from common import make_library_id, parse_library_id, slugify

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "vulns.db"
DEFAULT_RAW_ROOT = ROOT / "data" / "raw"

TOOLING_QUALIFIERS = {"test", "build", "module-load"}

DEFAULT_GITHUB_ORG = "finos"
DEFAULT_GITHUB_API = "https://api.github.com"
DEFAULT_GITHUB_PARALLELISM = 16
DEFAULT_GITHUB_TIMEOUT_SECONDS = 25
DEFAULT_GITHUB_MAX_MANIFESTS_PER_REPO = 12

ROOT_MANIFEST_NAMES = {
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "requirements-dev.txt",
    "requirements.in",
}

DEEP_MANIFEST_BASENAMES = {
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "requirements.in",
}

LIBRARY_ITSO = {
    ("maven", "org.springframework", "spring-web"): ("spring-framework", "spring-maintainers@example.org", "Shared Infrastructure"),
    ("maven", "org.springframework", "spring-context"): ("spring-framework", "spring-maintainers@example.org", "Shared Infrastructure"),
    ("maven", "org.springframework", "spring-beans"): ("spring-framework", "spring-maintainers@example.org", "Shared Infrastructure"),
    ("maven", "org.springframework", "spring-webmvc"): ("spring-framework", "spring-maintainers@example.org", "Shared Infrastructure"),
    ("maven", "org.yaml", "snakeyaml"): ("yaml-utils", "yaml-maintainers@example.org", "Shared Infrastructure"),
    ("maven", "org.apache.logging.log4j", "log4j-core"): ("logging-platform", "logging@example.org", "Shared Infrastructure"),
    ("maven", "io.netty", "netty-codec-http2"): ("network-core", "network@example.org", "Shared Infrastructure"),
    ("maven", "org.apache.activemq", "activemq-client"): ("messaging-core", "messaging@example.org", "Operations"),
    ("maven", "org.bitbucket.b_c", "jose4j"): ("identity-core", "identity@example.org", "Identity"),
    ("maven", "com.fasterxml.jackson.core", "jackson-databind"): ("serialization-core", "serialization@example.org", "Shared Infrastructure"),
    ("rpm", "rhel", "xz"): ("rhel-base", "os-platform@example.org", "Infra Operations"),
}

VERSION_CHAIN_CANDIDATES = {
    ("maven", "org.springframework", "spring-web"): ["5.3.30", "5.3.31", "5.3.39", "5.3.40", "6.0.0", "6.0.23"],
    ("maven", "org.springframework", "spring-context"): ["5.3.31", "5.3.39", "5.3.40", "6.0.0", "6.0.23"],
    ("maven", "org.springframework", "spring-beans"): ["5.3.10", "5.3.17", "5.3.18", "5.3.31", "6.0.0"],
    ("maven", "org.springframework", "spring-webmvc"): ["6.1.0", "6.1.3", "6.1.4", "6.2.0"],
    ("maven", "org.yaml", "snakeyaml"): ["1.29", "1.30", "1.33", "2.0", "2.2"],
    ("maven", "org.apache.logging.log4j", "log4j-core"): ["2.12.0", "2.14.1", "2.15.0", "2.16.0", "2.17.1", "2.22.1"],
    ("maven", "io.netty", "netty-codec-http2"): ["4.1.86.Final", "4.1.94.Final", "4.1.99.Final", "4.1.100.Final", "4.1.112.Final"],
    ("maven", "org.apache.activemq", "activemq-client"): ["5.15.8", "5.16.6", "5.17.2", "5.17.6", "5.18.3"],
    ("maven", "org.bitbucket.b_c", "jose4j"): ["0.7.9", "0.8.0", "0.9.2", "0.9.3"],
    ("maven", "com.fasterxml.jackson.core", "jackson-databind"): ["2.14.0", "2.14.2", "2.15.3", "2.15.4", "2.17.0"],
    ("rpm", "rhel", "xz"): ["5.4.3-1", "5.4.4-1", "5.4.5-1", "5.4.6-2", "5.6.2-1"],
}


@dataclass
class Project:
    id: str
    namespace: str
    meta: str
    proj: str
    release: str
    project_ref: str
    eonid: str
    department: str
    tai_system: str


@dataclass
class DepEdge:
    consumer_id: str
    library_id: str
    direct: int
    qualifier: str
    parent_id: str = ""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_github_token(explicit_token: Optional[str]) -> Optional[str]:
    if explicit_token:
        return explicit_token.strip()
    try:
        token = subprocess.check_output(["gh", "auth", "token"], text=True, stderr=subprocess.DEVNULL).strip()
        return token or None
    except Exception:
        return None


def github_get_json(url: str, token: Optional[str], timeout_seconds: int = DEFAULT_GITHUB_TIMEOUT_SECONDS, retries: int = 2) -> Dict[str, object]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "risk-navigator/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                payload = resp.read().decode("utf-8")
            data = json.loads(payload)
            if isinstance(data, dict):
                return data
            return {"data": data}
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code in (403, 429):
                reset_raw = exc.headers.get("X-RateLimit-Reset", "") if exc.headers else ""
                if reset_raw.isdigit():
                    sleep_seconds = max(1, int(reset_raw) - int(time.time()))
                    time.sleep(min(sleep_seconds, 30))
                    continue
            if exc.code >= 500 and attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        except Exception as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
    if last_err:
        raise last_err
    return {}


def github_get_repo_content(
    owner: str,
    repo: str,
    path: str,
    ref: str,
    token: Optional[str],
    github_api_base: str,
    timeout_seconds: int,
) -> str:
    quoted_path = urllib.parse.quote(path, safe="/")
    qref = urllib.parse.urlencode({"ref": ref})
    url = f"{github_api_base}/repos/{owner}/{repo}/contents/{quoted_path}?{qref}"
    obj = github_get_json(url, token=token, timeout_seconds=timeout_seconds, retries=1)
    encoded = str(obj.get("content") or "")
    encoding = str(obj.get("encoding") or "")
    if not encoded:
        return ""
    if encoding == "base64":
        import base64

        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    return encoded


def normalize_version_text(raw: str) -> str:
    value = raw.strip().strip('"').strip("'")
    if not value:
        return "unspecified"
    if value.startswith(("^", "~", ">", "<", "=")):
        value = re.sub(r"^[\^~<>=\s]+", "", value)
    if " " in value:
        first = value.split(" ", 1)[0]
        if first:
            value = first
    if "," in value:
        first = value.split(",", 1)[0]
        if first:
            value = first
    return value or "unspecified"


def maven_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1]


def parse_maven_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    if not text.strip():
        return deps

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return deps

    properties: Dict[str, str] = {}
    for prop_node in root.findall(".//{*}properties"):
        for child in list(prop_node):
            key = maven_namespace(child.tag)
            value = (child.text or "").strip()
            if key and value:
                properties[key] = value

    for dep in root.findall(".//{*}dependencies/{*}dependency"):
        group_id = (dep.findtext("{*}groupId") or "").strip()
        artifact_id = (dep.findtext("{*}artifactId") or "").strip()
        version = (dep.findtext("{*}version") or "").strip()
        scope = (dep.findtext("{*}scope") or "runtime").strip().lower()
        optional = (dep.findtext("{*}optional") or "false").strip().lower()
        if not group_id or not artifact_id:
            continue
        if version.startswith("${") and version.endswith("}"):
            key = version[2:-1].strip()
            version = properties.get(key, version)
        release = normalize_version_text(version or "unspecified")
        qualifier = "test" if scope == "test" else ("build" if optional == "true" else "runtime")
        deps.append(("maven", group_id, artifact_id, release, qualifier))
    return deps


GRADLE_DEP_RE = re.compile(
    r"""(?P<cfg>[A-Za-z0-9_]+)\s*\(?\s*['"](?P<ga>[^'"]+)['"]\s*\)?"""
)


def parse_gradle_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        match = GRADLE_DEP_RE.search(stripped)
        if not match:
            continue
        cfg = match.group("cfg").lower()
        ga = match.group("ga").strip()
        if ":" not in ga:
            continue
        parts = ga.split(":")
        if len(parts) < 3:
            continue
        group_id, artifact_id = parts[0].strip(), parts[1].strip()
        version = normalize_version_text(parts[2].strip())
        if not group_id or not artifact_id:
            continue
        qualifier = "test" if cfg.startswith("test") else "runtime"
        deps.append(("maven", group_id, artifact_id, version, qualifier))
    return deps


def parse_npm_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    try:
        payload = json.loads(text)
    except Exception:
        return deps

    if not isinstance(payload, dict):
        return deps

    for section, qualifier in [("dependencies", "runtime"), ("devDependencies", "test")]:
        block = payload.get(section, {})
        if not isinstance(block, dict):
            continue
        for name, version_raw in block.items():
            if not isinstance(name, str):
                continue
            version = normalize_version_text(str(version_raw or "unspecified"))
            meta = ""
            proj = name
            if name.startswith("@") and "/" in name:
                meta, proj = name.split("/", 1)
            deps.append(("npm", meta, proj, version, qualifier))
    return deps


REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~]{1,2})?\s*([^;#\s]+)?")


def parse_requirements_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("-r ") or raw.startswith("--"):
            continue
        match = REQ_RE.match(raw)
        if not match:
            continue
        name = match.group(1) or ""
        version = normalize_version_text(match.group(3) or "unspecified")
        if not name:
            continue
        deps.append(("pypi", "", name.lower(), version, "runtime"))
    return deps


def parse_pyproject_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    if tomllib is None:
        return deps
    try:
        payload = tomllib.loads(text)
    except Exception:
        return deps
    if not isinstance(payload, dict):
        return deps

    # Pipfile format
    for section, qualifier in [("packages", "runtime"), ("dev-packages", "test")]:
        block = payload.get(section, {})
        if isinstance(block, dict):
            for name, version_raw in block.items():
                if not isinstance(name, str):
                    continue
                version = "unspecified"
                if isinstance(version_raw, str):
                    version = normalize_version_text(version_raw)
                elif isinstance(version_raw, dict):
                    version = normalize_version_text(str(version_raw.get("version", "unspecified")))
                deps.append(("pypi", "", name.lower(), version, qualifier))

    project = payload.get("project", {})
    if isinstance(project, dict):
        dep_list = project.get("dependencies", [])
        if isinstance(dep_list, list):
            for row in dep_list:
                if not isinstance(row, str):
                    continue
                match = REQ_RE.match(row.strip())
                if not match:
                    continue
                name = match.group(1) or ""
                version = normalize_version_text(match.group(3) or "unspecified")
                if name:
                    deps.append(("pypi", "", name.lower(), version, "runtime"))

        opt = project.get("optional-dependencies", {})
        if isinstance(opt, dict):
            for dep_rows in opt.values():
                if not isinstance(dep_rows, list):
                    continue
                for row in dep_rows:
                    if not isinstance(row, str):
                        continue
                    match = REQ_RE.match(row.strip())
                    if not match:
                        continue
                    name = match.group(1) or ""
                    version = normalize_version_text(match.group(3) or "unspecified")
                    if name:
                        deps.append(("pypi", "", name.lower(), version, "test"))
    return deps


DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)", flags=re.IGNORECASE)


def parse_image_reference(image: str) -> Tuple[str, str, str, str]:
    image = image.strip()
    if not image:
        return ("oci", "", "unknown", "latest")
    image_no_digest = image.split("@", 1)[0]
    if ":" in image_no_digest:
        path, tag = image_no_digest.rsplit(":", 1)
    else:
        path, tag = image_no_digest, "latest"
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return ("oci", "", "unknown", normalize_version_text(tag))
    if len(segments) == 1:
        return ("oci", "docker.io/library", segments[0], normalize_version_text(tag))
    repo = segments[-1]
    meta = "/".join(segments[:-1])
    return ("oci", meta, repo, normalize_version_text(tag))


def parse_dockerfile_dependencies(text: str) -> List[Tuple[str, str, str, str, str]]:
    deps: List[Tuple[str, str, str, str, str]] = []
    for line in text.splitlines():
        match = DOCKER_FROM_RE.match(line)
        if not match:
            continue
        image = match.group(1)
        namespace, meta, proj, version = parse_image_reference(image)
        deps.append((namespace, meta, proj, version, "runtime"))
    return deps


def sample_projects() -> List[Project]:
    repos = [
        "legend-studio",
        "perspective-viewer",
        "fdb-relational-core",
        "symphony-bdk-java",
        "openfin-java-integration",
        "finos-tracers",
        "cloud-events-router",
        "risk-aggregation-service",
        "trade-api-gateway",
        "clearing-ledger-sync",
        "reg-reporting-engine",
        "market-data-distributor",
        "ops-batch-orchestrator",
        "connectivity-hub",
        "authz-policy-engine",
        "portfolio-calc-engine",
        "credit-risk-scoring",
        "liquidity-watch",
        "compliance-audit-stream",
        "reference-data-core",
        "payments-scheduler",
        "eod-reconciliation",
        "vault-signing-proxy",
        "container-baseline-audit",
    ]
    departments = [
        "Capital Markets",
        "Risk Platforms",
        "Operations",
        "Shared Infrastructure",
    ]
    out: List[Project] = []
    for idx, repo in enumerate(repos):
        dept = departments[idx % len(departments)]
        project_id = f"github|finos|{repo}"
        out.append(
            Project(
                id=project_id,
                namespace=project_id.split("|", 1)[0],
                meta=project_id.split("|")[1],
                proj=repo,
                release=f"1.0.{idx}",
                project_ref=f"github/finos/{repo}",
                eonid=f"FIN-{1000 + idx}",
                department=dept,
                tai_system=repo.replace("-", "_").upper(),
            )
        )
    return out


def lib(namespace: str, meta: str, proj: str, release: str) -> str:
    return make_library_id(namespace, meta, proj, release)


def sample_edges(projects: Sequence[Project]) -> List[DepEdge]:
    base_direct = [
        (lib("maven", "org.springframework.boot", "spring-boot-starter-web", "2.7.18"), 1, "runtime", ""),
        (lib("maven", "com.fasterxml.jackson.core", "jackson-databind", "2.14.2"), 1, "runtime", ""),
        (lib("maven", "ch.qos.logback", "logback-classic", "1.2.11"), 1, "runtime", ""),
        (lib("maven", "org.junit.jupiter", "junit-jupiter", "5.10.1"), 1, "test", ""),
    ]

    transitive_from_web = [
        (lib("maven", "org.springframework", "spring-web", "5.3.39"), 0, "runtime", lib("maven", "org.springframework.boot", "spring-boot-starter-web", "2.7.18")),
        (lib("maven", "org.springframework", "spring-context", "5.3.39"), 0, "runtime", lib("maven", "org.springframework.boot", "spring-boot-starter-web", "2.7.18")),
        (lib("maven", "org.springframework", "spring-beans", "5.3.17"), 0, "runtime", lib("maven", "org.springframework.boot", "spring-boot-starter-web", "2.7.18")),
        (lib("maven", "org.yaml", "snakeyaml", "1.33"), 0, "runtime", lib("maven", "org.springframework.boot", "spring-boot-starter-web", "2.7.18")),
    ]

    transitive_reactive = [
        (lib("maven", "org.springframework.boot", "spring-boot-starter-webflux", "2.7.18"), 1, "runtime", ""),
        (lib("maven", "io.projectreactor.netty", "reactor-netty-http", "1.0.39"), 0, "runtime", lib("maven", "org.springframework.boot", "spring-boot-starter-webflux", "2.7.18")),
        (lib("maven", "io.netty", "netty-codec-http2", "4.1.99.Final"), 0, "runtime", lib("maven", "io.projectreactor.netty", "reactor-netty-http", "1.0.39")),
    ]

    messaging_set = [
        (lib("maven", "org.apache.camel", "camel-activemq", "3.20.6"), 1, "runtime", ""),
        (lib("maven", "org.apache.activemq", "activemq-client", "5.17.2"), 0, "runtime", lib("maven", "org.apache.camel", "camel-activemq", "3.20.6")),
    ]

    identity_set = [
        (lib("maven", "org.bitbucket.b_c", "jose4j", "0.9.2"), 1, "runtime", ""),
    ]

    log4j_set = [
        (lib("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"), 1, "runtime", ""),
    ]

    modern_set = [
        (lib("maven", "org.springframework", "spring-webmvc", "6.1.3"), 1, "runtime", ""),
    ]

    container_set = [
        (lib("rpm", "rhel", "xz", "5.4.5-1"), 1, "runtime", ""),
    ]

    edges: List[DepEdge] = []
    for idx, project in enumerate(projects):
        profile = list(base_direct)

        if project.namespace == "rpm":
            profile = list(container_set)
        else:
            profile.extend(transitive_from_web)
            if idx % 2 == 0:
                profile.extend(transitive_reactive)
            if idx % 3 == 0:
                profile.extend(messaging_set)
            if idx % 4 == 0:
                profile.extend(identity_set)
            if idx % 5 == 0:
                profile.extend(log4j_set)
            if idx % 6 == 0:
                profile.extend(modern_set)

        for library_id, direct, qualifier, parent in profile:
            edges.append(
                DepEdge(
                    consumer_id=project.id,
                    library_id=library_id,
                    direct=direct,
                    qualifier=qualifier,
                    parent_id=parent,
                )
            )

    dedup = {}
    for edge in edges:
        key = (edge.consumer_id, edge.library_id, edge.direct, edge.qualifier)
        if key not in dedup:
            dedup[key] = edge
    return list(dedup.values())


def manifest_paths_from_tree(tree_entries: Sequence[Dict[str, object]], max_manifests_per_repo: int) -> List[str]:
    paths: List[str] = []
    for entry in tree_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "blob":
            continue
        path = str(entry.get("path") or "")
        if not path:
            continue
        base = Path(path).name
        if "/" not in path:
            if base in ROOT_MANIFEST_NAMES or base.lower().startswith("dockerfile"):
                paths.append(path)
            continue
        if base in DEEP_MANIFEST_BASENAMES or base.lower().startswith("dockerfile"):
            parts = Path(path).parts
            if any(seg in {".github", "docs", "examples", "demo", "samples", "test", "tests"} for seg in parts):
                continue
            paths.append(path)
    unique = sorted(set(paths))
    return unique[:max_manifests_per_repo]


def list_org_repositories(
    org: str,
    token: Optional[str],
    github_api_base: str,
    timeout_seconds: int,
    include_archived: bool,
    max_repos: int,
) -> List[Dict[str, object]]:
    repos: List[Dict[str, object]] = []
    page = 1
    per_page = 100
    while True:
        q = urllib.parse.urlencode(
            {
                "type": "public",
                "sort": "pushed",
                "direction": "desc",
                "per_page": per_page,
                "page": page,
            }
        )
        url = f"{github_api_base}/orgs/{org}/repos?{q}"
        obj = github_get_json(url, token=token, timeout_seconds=timeout_seconds, retries=2)
        page_rows = obj if isinstance(obj, list) else obj.get("data", [])
        if not isinstance(page_rows, list) or not page_rows:
            break
        for row in page_rows:
            if not isinstance(row, dict):
                continue
            if row.get("fork"):
                continue
            if row.get("disabled"):
                continue
            if row.get("archived") and not include_archived:
                continue
            repos.append(row)
            if max_repos > 0 and len(repos) >= max_repos:
                return repos
        if len(page_rows) < per_page:
            break
        page += 1
    return repos


def parse_manifest_dependencies(path: str, content: str) -> List[Tuple[str, str, str, str, str]]:
    lower = path.lower()
    if lower.endswith("pom.xml"):
        return parse_maven_dependencies(content)
    if lower.endswith("build.gradle") or lower.endswith("build.gradle.kts"):
        return parse_gradle_dependencies(content)
    if lower.endswith("package.json"):
        return parse_npm_dependencies(content)
    if lower.endswith("requirements.txt") or lower.endswith("requirements.in") or lower.endswith("requirements-dev.txt"):
        return parse_requirements_dependencies(content)
    if lower.endswith("pyproject.toml") or lower.endswith("pipfile"):
        return parse_pyproject_dependencies(content)
    if Path(lower).name.startswith("dockerfile"):
        return parse_dockerfile_dependencies(content)
    return []


def edges_for_repo(
    owner: str,
    repo_name: str,
    default_branch: str,
    project_id: str,
    token: Optional[str],
    github_api_base: str,
    timeout_seconds: int,
    max_manifests_per_repo: int,
) -> List[DepEdge]:
    tree_url = f"{github_api_base}/repos/{owner}/{repo_name}/git/trees/{urllib.parse.quote(default_branch, safe='')}?recursive=1"
    tree_obj = github_get_json(tree_url, token=token, timeout_seconds=timeout_seconds, retries=1)
    entries = tree_obj.get("tree", []) if isinstance(tree_obj, dict) else []
    if not isinstance(entries, list):
        entries = []

    manifest_paths = manifest_paths_from_tree(entries, max_manifests_per_repo=max_manifests_per_repo)
    edges: List[DepEdge] = []
    seen: set = set()
    for path in manifest_paths:
        content = github_get_repo_content(
            owner,
            repo_name,
            path=path,
            ref=default_branch,
            token=token,
            github_api_base=github_api_base,
            timeout_seconds=timeout_seconds,
        )
        if not content:
            continue
        for namespace, meta, proj, release, qualifier in parse_manifest_dependencies(path, content):
            if not namespace or not proj:
                continue
            lid = make_library_id(namespace, meta, proj, normalize_version_text(release))
            key = (project_id, lid, qualifier)
            if key in seen:
                continue
            seen.add(key)
            edges.append(DepEdge(consumer_id=project_id, library_id=lid, direct=1, qualifier=qualifier, parent_id=""))
    return edges


def load_vuln_edges(db_path: Path) -> Dict[str, List[Dict[str, object]]]:
    if not db_path.exists():
        return {}

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT cve_id, namespace, meta, proj, release, cvss, priority, exploitability
            FROM vuln_version_edges
            """
        ).fetchall()
    finally:
        conn.close()

    out: Dict[str, List[Dict[str, object]]] = defaultdict(list)
    for row in rows:
        lid = make_library_id(row["namespace"], row["meta"], row["proj"], row["release"])
        out[lid].append(
            {
                "cve_id": row["cve_id"],
                "cvss": float(row["cvss"] or 0.0),
                "priority": row["priority"] or "P4",
                "exploitability": row["exploitability"] or "UNPROVEN",
            }
        )
    return out


def write_csv(path: Path, rows: Sequence[Dict[str, object]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_version_chain_rows(
    vulnerable_keys: Sequence[Tuple[str, str, str]],
    vuln_edge_map: Dict[str, List[Dict[str, object]]],
) -> List[Dict[str, object]]:
    rows = []
    release_id = 1000
    for key in sorted(set(vulnerable_keys)):
        namespace, meta, proj = key
        releases = list(VERSION_CHAIN_CANDIDATES.get(key, []))
        # ensure versions that came from vuln ingestion are represented
        for lid in vuln_edge_map.keys():
            ns, me, pr, rel = parse_library_id(lid)
            if (ns, me, pr) == key and rel not in releases:
                releases.append(rel)

        def sort_key(ver: str) -> Tuple[int, ...]:
            nums = []
            token = ""
            for ch in ver:
                if ch.isdigit():
                    token += ch
                elif token:
                    nums.append(int(token))
                    token = ""
            if token:
                nums.append(int(token))
            while len(nums) < 4:
                nums.append(0)
            return tuple(nums[:6])

        releases.sort(key=sort_key)

        for rel in releases:
            lid = make_library_id(namespace, meta, proj, rel)
            cves = vuln_edge_map.get(lid, [])
            max_cvss = max((float(item["cvss"]) for item in cves), default=0.0)
            rows.append(
                {
                    "library_id": lid,
                    "namespace": namespace,
                    "meta": meta,
                    "proj": proj,
                    "release": rel,
                    "release_id": release_id,
                    "max_cvss": round(max_cvss, 1),
                    "cve_count": len(cves),
                }
            )
            release_id += 1
    return rows


def write_scope_extract(scope: str, projects: Sequence[Project], edges: Sequence[DepEdge], db_path: Path, raw_root: Path) -> Dict[str, object]:
    vuln_edge_map = load_vuln_edges(db_path)

    raw_dir = raw_root / scope
    raw_dir.mkdir(parents=True, exist_ok=True)

    project_rows = [
        {
            "id": p.id,
            "namespace": p.namespace,
            "meta": p.meta,
            "proj": p.proj,
            "release": p.release,
            "project_ref": p.project_ref,
            "eonid": p.eonid,
            "department": p.department,
            "tai_system": p.tai_system,
        }
        for p in projects
    ]

    dep_rows = [
        {
            "consumer_id": e.consumer_id,
            "library_id": e.library_id,
            "direct": e.direct,
            "qualifier": e.qualifier,
            "parent_id": e.parent_id,
        }
        for e in edges
    ]

    libs_in_graph = {e.library_id for e in edges}
    cve_lib_rows: List[Dict[str, object]] = []
    cve_edge_rows: List[Dict[str, object]] = []

    vulnerable_keys: List[Tuple[str, str, str]] = []

    for library_id in sorted(libs_in_graph):
        cve_rows = vuln_edge_map.get(library_id, [])
        if not cve_rows:
            continue
        namespace, meta, proj, release = parse_library_id(library_id)
        vulnerable_keys.append((namespace, meta, proj))
        max_cvss = max(float(item["cvss"]) for item in cve_rows)

        highest_priority = sorted((item["priority"] for item in cve_rows), key=lambda p: (p != "P1", p))[0]
        max_expl = sorted((item["exploitability"] for item in cve_rows), reverse=True)[0]

        tai, owner, dept = LIBRARY_ITSO.get((namespace, meta, proj), ("unknown", "unknown@example.org", "Unknown"))

        cve_lib_rows.append(
            {
                "library_id": library_id,
                "namespace": namespace,
                "meta": meta,
                "proj": proj,
                "release": release,
                "max_cvss": round(max_cvss, 1),
                "cve_count": len(cve_rows),
                "highest_priority": highest_priority,
                "max_exploitability": max_expl,
                "lib_tai_system": tai,
                "lib_primary_owner": owner,
                "lib_dept": dept,
            }
        )

        for item in cve_rows:
            cve_edge_rows.append(
                {
                    "library_id": library_id,
                    "cve_id": item["cve_id"],
                    "cvss_base": round(float(item["cvss"]), 1),
                    "cvss_temporal": round(float(item["cvss"]), 1),
                    "priority": item["priority"],
                    "exploitability": item["exploitability"],
                }
            )

    version_chain_rows = build_version_chain_rows(vulnerable_keys, vuln_edge_map)

    # Amplifiers derive from parent ids on transitive vulnerable edges.
    amp_counter: Dict[Tuple[str, str], set] = defaultdict(set)
    for edge in edges:
        if edge.direct:
            continue
        if not edge.parent_id:
            continue
        if edge.library_id not in {row["library_id"] for row in cve_lib_rows}:
            continue
        amp_counter[(edge.library_id, edge.parent_id)].add(edge.consumer_id)

    amp_rows = []
    for (cve_lib_id, amp_id), consumers in sorted(amp_counter.items()):
        c_ns, c_meta, c_proj, c_rel = parse_library_id(cve_lib_id)
        a_ns, a_meta, a_proj, a_rel = parse_library_id(amp_id)
        amp_rows.append(
            {
                "cve_lib_id": cve_lib_id,
                "cve_lib_coords": f"{c_ns}/{c_meta}/{c_proj}@{c_rel}",
                "amplifier_id": amp_id,
                "amplifier_coords": f"{a_ns}/{a_meta}/{a_proj}@{a_rel}",
                "root_projects_affected": len(consumers),
            }
        )

    write_csv(
        raw_dir / "01-consumer-projects.csv",
        project_rows,
        ["id", "namespace", "meta", "proj", "release", "project_ref", "eonid", "department", "tai_system"],
    )
    write_csv(
        raw_dir / "02-dep-edges.csv",
        dep_rows,
        ["consumer_id", "library_id", "direct", "qualifier", "parent_id"],
    )
    write_csv(
        raw_dir / "03-cve-libs.csv",
        cve_lib_rows,
        [
            "library_id",
            "namespace",
            "meta",
            "proj",
            "release",
            "max_cvss",
            "cve_count",
            "highest_priority",
            "max_exploitability",
            "lib_tai_system",
            "lib_primary_owner",
            "lib_dept",
        ],
    )
    write_csv(
        raw_dir / "04-version-chain.csv",
        version_chain_rows,
        ["library_id", "namespace", "meta", "proj", "release", "release_id", "max_cvss", "cve_count"],
    )
    write_csv(
        raw_dir / "05-amplifiers.csv",
        amp_rows,
        ["cve_lib_id", "cve_lib_coords", "amplifier_id", "amplifier_coords", "root_projects_affected"],
    )
    write_csv(
        raw_dir / "06-cve-edges.csv",
        cve_edge_rows,
        ["library_id", "cve_id", "cvss_base", "cvss_temporal", "priority", "exploitability"],
    )

    return {
        "scope": scope,
        "projects": len(project_rows),
        "dep_edges": len(dep_rows),
        "cve_libs": len(cve_lib_rows),
        "cve_edges": len(cve_edge_rows),
        "amplifiers": len(amp_rows),
    }


def extract_synthetic(scope: str, db_path: Path, raw_root: Path) -> Dict[str, object]:
    projects = sample_projects()
    edges = sample_edges(projects)
    return write_scope_extract(scope=scope, projects=projects, edges=edges, db_path=db_path, raw_root=raw_root)


def extract_finos_github_org(
    scope: str,
    db_path: Path,
    raw_root: Path,
    github_org: str,
    github_token: Optional[str],
    github_api_base: str,
    include_archived: bool,
    max_repos: int,
    parallelism: int,
    timeout_seconds: int,
    max_manifests_per_repo: int,
) -> Dict[str, object]:
    token = get_github_token(github_token)
    repos = list_org_repositories(
        org=github_org,
        token=token,
        github_api_base=github_api_base,
        timeout_seconds=timeout_seconds,
        include_archived=include_archived,
        max_repos=max_repos,
    )

    projects: List[Project] = []
    for idx, row in enumerate(repos):
        name = str(row.get("name") or "")
        if not name:
            continue
        default_branch = str(row.get("default_branch") or "main")
        proj_id = f"github|{github_org}|{name}"
        topics = row.get("topics", [])
        department = "FINOS OSS"
        if isinstance(topics, list) and topics:
            first_topic = next((str(x) for x in topics if str(x).strip()), "")
            if first_topic:
                department = first_topic
        projects.append(
            Project(
                id=proj_id,
                namespace="github",
                meta=github_org,
                proj=name,
                release=default_branch,
                project_ref=f"github/{github_org}/{name}",
                eonid=f"FINOS-{10000 + idx}",
                department=department,
                tai_system=name.replace("-", "_").upper(),
            )
        )

    dep_edges: List[DepEdge] = []
    failures: List[str] = []
    repo_rows_by_name = {str(row.get("name") or ""): row for row in repos}

    with ThreadPoolExecutor(max_workers=max(1, parallelism)) as pool:
        futures = {}
        for project in projects:
            repo_row = repo_rows_by_name.get(project.proj, {})
            default_branch = str(repo_row.get("default_branch") or project.release or "main")
            fut = pool.submit(
                edges_for_repo,
                github_org,
                project.proj,
                default_branch,
                project.id,
                token,
                github_api_base,
                timeout_seconds,
                max_manifests_per_repo,
            )
            futures[fut] = project.proj

        for fut in as_completed(futures):
            repo_name = futures[fut]
            try:
                dep_edges.extend(fut.result())
            except Exception as exc:
                failures.append(f"{repo_name}: {exc}")

    stats = write_scope_extract(scope=scope, projects=projects, edges=dep_edges, db_path=db_path, raw_root=raw_root)
    stats["github_org"] = github_org
    stats["repo_failures"] = len(failures)
    stats["repos_total"] = len(projects)
    stats["repos_with_deps"] = len({edge.consumer_id for edge in dep_edges})
    stats["github_token_used"] = bool(token)
    if failures:
        sample = failures[:20]
        stats["failure_examples"] = sample
    return stats


def extract_from_cyclonedx(scope: str, sbom_dir: Path, raw_root: Path) -> Dict[str, object]:
    """Minimal CycloneDX importer for organizations with existing SBOM dumps."""

    projects: List[Project] = []
    edges: List[DepEdge] = []

    for sbom_file in sorted(sbom_dir.glob("*.json")):
        with open(sbom_file, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        metadata = payload.get("metadata") or {}
        component = metadata.get("component") or {}
        comp_name = str(component.get("name") or sbom_file.stem)
        comp_version = str(component.get("version") or "0.0.0")
        project_id = f"github|imported|{slugify(comp_name)}"
        projects.append(
            Project(
                id=project_id,
                namespace="github",
                meta="imported",
                proj=slugify(comp_name),
                release=comp_version,
                project_ref=f"sbom/{sbom_file.name}",
                eonid=f"SBOM-{len(projects)+1}",
                department="Imported",
                tai_system=comp_name,
            )
        )

        components = payload.get("components") or []
        for comp in components:
            if not isinstance(comp, dict):
                continue
            purl = str(comp.get("purl") or "")
            if not purl.startswith("pkg:"):
                continue
            # purl format: pkg:maven/group/artifact@version
            release = purl.split("@")[-1] if "@" in purl else "0"
            path = purl.split(":", 1)[1].split("@", 1)[0]
            namespace = path.split("/", 1)[0]
            rest = path.split("/", 1)[1] if "/" in path else path
            if namespace == "maven" and "/" in rest:
                meta, proj = rest.split("/", 1)
            else:
                meta, proj = "", rest
            library_id = make_library_id(namespace, meta, proj, release)
            edges.append(DepEdge(project_id, library_id, 1, "runtime"))

    raw_dir = raw_root / scope
    raw_dir.mkdir(parents=True, exist_ok=True)

    write_csv(
        raw_dir / "01-consumer-projects.csv",
        [
            {
                "id": p.id,
                "namespace": p.namespace,
                "meta": p.meta,
                "proj": p.proj,
                "release": p.release,
                "project_ref": p.project_ref,
                "eonid": p.eonid,
                "department": p.department,
                "tai_system": p.tai_system,
            }
            for p in projects
        ],
        ["id", "namespace", "meta", "proj", "release", "project_ref", "eonid", "department", "tai_system"],
    )
    write_csv(
        raw_dir / "02-dep-edges.csv",
        [
            {
                "consumer_id": e.consumer_id,
                "library_id": e.library_id,
                "direct": e.direct,
                "qualifier": e.qualifier,
                "parent_id": e.parent_id,
            }
            for e in edges
        ],
        ["consumer_id", "library_id", "direct", "qualifier", "parent_id"],
    )

    # placeholders; build_dataset will join against vuln DB and fill coverage where possible.
    for name, cols in [
        ("03-cve-libs.csv", ["library_id", "namespace", "meta", "proj", "release", "max_cvss", "cve_count", "highest_priority", "max_exploitability", "lib_tai_system", "lib_primary_owner", "lib_dept"]),
        ("04-version-chain.csv", ["library_id", "namespace", "meta", "proj", "release", "release_id", "max_cvss", "cve_count"]),
        ("05-amplifiers.csv", ["cve_lib_id", "cve_lib_coords", "amplifier_id", "amplifier_coords", "root_projects_affected"]),
        ("06-cve-edges.csv", ["library_id", "cve_id", "cvss_base", "cvss_temporal", "priority", "exploitability"]),
    ]:
        write_csv(raw_dir / name, [], cols)

    return {
        "scope": scope,
        "projects": len(projects),
        "dep_edges": len(edges),
        "cve_libs": 0,
        "cve_edges": 0,
        "amplifiers": 0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", default="finos-sample-platform")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--source", choices=["synthetic", "cyclonedx", "finos-github"], default="synthetic")
    parser.add_argument("--sbom-dir", type=Path, help="Directory containing CycloneDX JSON documents")
    parser.add_argument("--github-org", default=DEFAULT_GITHUB_ORG)
    parser.add_argument("--github-token", default="", help="Optional GitHub token; falls back to gh auth token when available")
    parser.add_argument("--github-api-base", default=DEFAULT_GITHUB_API)
    parser.add_argument("--github-include-archived", action="store_true")
    parser.add_argument("--github-max-repos", type=int, default=0, help="0 means all repos")
    parser.add_argument("--github-parallelism", type=int, default=DEFAULT_GITHUB_PARALLELISM)
    parser.add_argument("--github-timeout-seconds", type=int, default=DEFAULT_GITHUB_TIMEOUT_SECONDS)
    parser.add_argument("--github-max-manifests-per-repo", type=int, default=DEFAULT_GITHUB_MAX_MANIFESTS_PER_REPO)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.source == "synthetic":
        stats = extract_synthetic(args.scope, args.db, args.raw_root)
    elif args.source == "cyclonedx":
        if not args.sbom_dir:
            raise SystemExit("--sbom-dir is required for --source cyclonedx")
        stats = extract_from_cyclonedx(args.scope, args.sbom_dir, args.raw_root)
    else:
        stats = extract_finos_github_org(
            scope=args.scope,
            db_path=args.db,
            raw_root=args.raw_root,
            github_org=args.github_org,
            github_token=str(args.github_token or "").strip() or None,
            github_api_base=args.github_api_base.rstrip("/"),
            include_archived=bool(args.github_include_archived),
            max_repos=max(0, int(args.github_max_repos or 0)),
            parallelism=max(1, int(args.github_parallelism or 1)),
            timeout_seconds=max(5, int(args.github_timeout_seconds or DEFAULT_GITHUB_TIMEOUT_SECONDS)),
            max_manifests_per_repo=max(1, int(args.github_max_manifests_per_repo or DEFAULT_GITHUB_MAX_MANIFESTS_PER_REPO)),
        )

    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

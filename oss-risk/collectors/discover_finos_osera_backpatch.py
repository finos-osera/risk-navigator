#!/usr/bin/env python3
"""Discover FINOS OSERA backpatch repositories as OSS risk seed records."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "oss-risk" / "data" / "finos-osera-backpatch-libraries.json"
ORG = "finos-osera"
PREFIX = "backpatch-"

COORDINATE_OVERRIDES = {
    "activemq": "org.apache.activemq:activemq-client",
    "avatica-core": "org.apache.calcite.avatica:avatica-core",
    "bouncycastle": "org.bouncycastle:bcprov-jdk18on",
    "camel": "org.apache.camel:camel-core",
    "commons-beanutils": "commons-beanutils:commons-beanutils",
    "commons-collections": "commons-collections:commons-collections",
    "commons-compress": "org.apache.commons:commons-compress",
    "commons-configuration2": "org.apache.commons:commons-configuration2",
    "commons-fileupload": "commons-fileupload:commons-fileupload",
    "commons-io": "commons-io:commons-io",
    "commons-lang": "commons-lang:commons-lang",
    "commons-text": "org.apache.commons:commons-text",
    "commons-vfs2": "org.apache.commons:commons-vfs2",
    "cxf": "org.apache.cxf:cxf-core",
    "dom4j": "org.dom4j:dom4j",
    "fastjson": "com.alibaba:fastjson",
    "graphql-java": "com.graphql-java:graphql-java",
    "gson": "com.google.code.gson:gson",
    "guava": "com.google.guava:guava",
    "h2": "com.h2database:h2",
    "hazelcast": "com.hazelcast:hazelcast",
    "hibernate-core": "org.hibernate:hibernate-core",
    "httpclient5": "org.apache.httpcomponents.client5:httpclient5",
    "jackson-databind": "com.fasterxml.jackson.core:jackson-databind",
    "jetty": "org.eclipse.jetty:jetty-server",
    "jodd-json": "org.jodd:jodd-json",
    "kafka-clients": "org.apache.kafka:kafka-clients",
    "log4j": "log4j:log4j",
    "log4j-core": "org.apache.logging.log4j:log4j-core",
    "logback": "ch.qos.logback:logback-core",
    "mina-core": "org.apache.mina:mina-core",
    "netty": "io.netty:netty-codec-http",
    "okhttp": "com.squareup.okhttp3:okhttp",
    "pac4j": "org.pac4j:pac4j-core",
    "protobuf-java": "com.google.protobuf:protobuf-java",
    "reactor-netty-http": "io.projectreactor.netty:reactor-netty-http",
    "snakeyaml": "org.yaml:snakeyaml",
    "spring-boot": "org.springframework.boot:spring-boot",
    "spring-cloud-config": "org.springframework.cloud:spring-cloud-config-server",
    "spring-cloud-function": "org.springframework.cloud:spring-cloud-function-core",
    "spring-cloud-gateway": "org.springframework.cloud:spring-cloud-gateway-server",
    "spring-data-commons": "org.springframework.data:spring-data-commons",
    "spring-framework": "org.springframework:spring-core",
    "spring-hateoas": "org.springframework.hateoas:spring-hateoas",
    "spring-integration-zip": "org.springframework.integration:spring-integration-zip",
    "spring-kafka": "org.springframework.kafka:spring-kafka",
    "spring-ldap": "org.springframework.ldap:spring-ldap-core",
    "spring-security": "org.springframework.security:spring-security-core",
    "spring-security-oauth2": "org.springframework.security.oauth:spring-security-oauth2",
    "spring-ws": "org.springframework.ws:spring-ws-core",
    "sshd-core": "org.apache.sshd:sshd-core",
    "struts2-core": "org.apache.struts:struts2-core",
    "tapestry": "tapestry:tapestry",
    "thymeleaf": "org.thymeleaf:thymeleaf",
    "tika-core": "org.apache.tika:tika-core",
    "tomcat-embed-core": "org.apache.tomcat.embed:tomcat-embed-core",
    "undertow-core": "io.undertow:undertow-core",
    "velocity-engine-core": "org.apache.velocity:velocity-engine-core",
    "xmlsec": "org.apache.santuario:xmlsec",
    "xstream": "com.thoughtworks.xstream:xstream",
}

UPSTREAM_OVERRIDES = {
    "activemq": "https://github.com/apache/activemq",
    "bouncycastle": "https://github.com/bcgit/bc-java",
    "camel": "https://github.com/apache/camel",
    "commons-collections": "https://github.com/apache/commons-collections",
    "commons-compress": "https://github.com/apache/commons-compress",
    "commons-lang": "https://github.com/apache/commons-lang",
    "commons-text": "https://github.com/apache/commons-text",
    "cxf": "https://github.com/apache/cxf",
    "dom4j": "https://github.com/dom4j/dom4j",
    "gson": "https://github.com/google/gson",
    "graphql-java": "https://github.com/graphql-java/graphql-java",
    "h2": "https://github.com/h2database/h2database",
    "jackson-databind": "https://github.com/FasterXML/jackson-databind",
    "jetty": "https://github.com/jetty/jetty.project",
    "kafka-clients": "https://github.com/apache/kafka",
    "log4j": "https://github.com/apache/logging-log4j1",
    "logback": "https://github.com/qos-ch/logback",
    "netty": "https://github.com/netty/netty",
    "okhttp": "https://github.com/square/okhttp",
    "pac4j": "https://github.com/pac4j/pac4j",
    "snakeyaml": "https://github.com/snakeyaml/snakeyaml",
    "spring-boot": "https://github.com/spring-projects/spring-boot",
    "spring-cloud-config": "https://github.com/spring-cloud/spring-cloud-config",
    "spring-cloud-gateway": "https://github.com/spring-cloud/spring-cloud-gateway",
    "spring-data-commons": "https://github.com/spring-projects/spring-data-commons",
    "spring-framework": "https://github.com/spring-projects/spring-framework",
    "spring-kafka": "https://github.com/spring-projects/spring-kafka",
    "spring-ldap": "https://github.com/spring-projects/spring-ldap",
    "spring-security": "https://github.com/spring-projects/spring-security",
    "spring-ws": "https://github.com/spring-projects/spring-ws",
    "struts2-core": "https://github.com/apache/struts",
    "tapestry": "https://github.com/apache/tapestry-4",
    "tomcat-embed-core": "https://github.com/apache/tomcat",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(["gh", "auth", "token"], check=True, capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


class GitHubClient:
    def __init__(self) -> None:
        self.token = github_token()

    def get(self, path: str) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "osera-oss-risk-discovery/0.1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = Request(f"https://api.github.com{path}", headers=headers)
        try:
            with urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"GitHub API HTTP {exc.code} for {path}: {body}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"GitHub API error for {path}: {exc}") from exc


def list_org_repos(client: GitHubClient, org: str) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    page = 1
    while True:
        batch = client.get(f"/orgs/{org}/repos?per_page=100&page={page}&type=all")
        if not isinstance(batch, list):
            raise RuntimeError(f"Unexpected repository response for {org}: {batch!r}")
        repos.extend(batch)
        if len(batch) < 100:
            return repos
        page += 1


def text_or_none(node: Optional[ET.Element]) -> Optional[str]:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def parse_pom(xml_text: str) -> Optional[Tuple[str, str]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}

    def find(path: str) -> Optional[ET.Element]:
        node = root.find(path, ns)
        if node is None:
            node = root.find(path.replace("m:", ""))
        return node

    group_id = text_or_none(find("m:groupId")) or text_or_none(find("m:parent/m:groupId"))
    artifact_id = text_or_none(find("m:artifactId"))
    if group_id and artifact_id and not group_id.startswith("${") and not artifact_id.startswith("${"):
        return group_id, artifact_id
    return None


def pom_candidates(client: GitHubClient, full_name: str, branch: str) -> List[str]:
    tree = client.get(f"/repos/{full_name}/git/trees/{quote(branch, safe='')}?recursive=1")
    if not isinstance(tree, dict):
        return []
    paths = []
    for row in tree.get("tree", []):
        path = row.get("path") or ""
        if path.endswith("pom.xml") and row.get("type") == "blob":
            paths.append(path)
    return paths


def read_repo_file(client: GitHubClient, full_name: str, path: str) -> Optional[str]:
    data = client.get(f"/repos/{full_name}/contents/{quote(path, safe='/')}")
    content = data.get("content") if isinstance(data, dict) else None
    encoding = data.get("encoding") if isinstance(data, dict) else None
    if not content or encoding != "base64":
        return None
    return base64.b64decode(content).decode("utf-8", errors="replace")


def discover_coordinate(client: GitHubClient, repo_full_name: str, default_branch: str, library_name: str) -> Tuple[Optional[str], str]:
    override = COORDINATE_OVERRIDES.get(library_name)
    if override:
        return override, "override"
    try:
        paths = pom_candidates(client, repo_full_name, default_branch)
    except RuntimeError:
        return None, "missing-pom-tree"
    parsed: List[Tuple[str, str, str]] = []
    for path in paths:
        try:
            content = read_repo_file(client, repo_full_name, path)
        except RuntimeError:
            continue
        coord = parse_pom(content or "")
        if coord:
            parsed.append((path, coord[0], coord[1]))
    for path, group_id, artifact_id in parsed:
        if artifact_id == library_name:
            return f"{group_id}:{artifact_id}", f"pom:{path}"
    for path, group_id, artifact_id in parsed:
        if path == "pom.xml":
            return f"{group_id}:{artifact_id}", "pom:pom.xml"
    if parsed:
        path, group_id, artifact_id = parsed[0]
        return f"{group_id}:{artifact_id}", f"pom:{path}"
    return None, "no-maven-coordinate"


def make_record(client: GitHubClient, repo: Dict[str, Any], observed_at: str) -> Optional[Dict[str, Any]]:
    repo_name = repo["name"]
    library_name = repo_name[len(PREFIX) :]
    full_name = repo["full_name"]
    default_branch = repo.get("default_branch") or "main"
    coordinate, coordinate_source = discover_coordinate(client, full_name, default_branch, library_name)
    if not coordinate:
        return None
    upstream_url = UPSTREAM_OVERRIDES.get(library_name)
    if not upstream_url and repo.get("fork"):
        detail = client.get(f"/repos/{full_name}")
        parent = detail.get("parent") or {}
        source = detail.get("source") or {}
        upstream_url = (source.get("html_url") or parent.get("html_url") or "").strip()
    upstream_url = upstream_url or repo.get("html_url")

    return {
        "schema_version": "0.1",
        "project": {
            "name": library_name,
            "ecosystem": "maven",
            "package": coordinate,
            "repository": upstream_url,
            "homepage": upstream_url,
        },
        "scores": {
            "project_vitality": 0,
            "security_health": 0,
            "sustainability_governance": 0,
            "dependency_hygiene": 0,
            "ecosystem_resilience": 0,
            "ecosystem_criticality": 0,
            "confidence": 0.3,
        },
        "evidence": {
            "finos_osera_backpatch": {
                "source": "github-org-discovery",
                "url": repo.get("html_url"),
                "observed_at": observed_at,
                "confidence": 0.9 if coordinate_source == "override" else 0.7,
                "backpatch_repository": full_name,
                "backpatch_name": repo_name,
                "library_name": library_name,
                "primary_language": (repo.get("language") or ""),
                "is_fork": bool(repo.get("fork")),
                "is_archived": bool(repo.get("archived")),
                "coordinate_source": coordinate_source,
                "upstream_repository": upstream_url,
                "description": repo.get("description") or "",
            }
        },
        "enterprise": {
            "versions_in_use": [],
            "application_count": 0,
            "direct_dependency_count": 0,
            "transitive_dependency_count": 0,
            "tier1_application_count": 0,
            "internet_facing_application_count": 0,
            "regulated_application_count": 0,
            "unsupported_version_count": 0,
            "known_vulnerable_version_count": 0,
        },
        "notes": [
            "Discovered from the current FINOS OSERA backpatch repository list.",
            "Enterprise exposure is unset until connected to SBOM or dependency inventory data.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover finos-osera/backpatch-* Maven libraries.")
    parser.add_argument("--org", default=ORG, help="GitHub organization to inspect")
    parser.add_argument("--prefix", default=PREFIX, help="Repository prefix to strip")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output seed JSON")
    args = parser.parse_args()

    client = GitHubClient()
    observed_at = now_iso()
    repos = [
        repo
        for repo in list_org_repos(client, args.org)
        if repo.get("name", "").startswith(args.prefix) and not repo.get("archived")
    ]
    records = []
    skipped = []
    for repo in sorted(repos, key=lambda row: row["name"]):
        record = make_record(client, repo, observed_at)
        if record:
            records.append(record)
        else:
            skipped.append(repo["full_name"])
    payload = {
        "schema_version": "0.1",
        "generated_at": observed_at,
        "source": f"github-org:{args.org}",
        "repository_prefix": args.prefix,
        "records": records,
        "skipped": skipped,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(records)} records to {args.output}")
    if skipped:
        print(f"Skipped {len(skipped)} repositories without Maven coordinates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate deterministic CycloneDX inputs for the FINOS deep SBOM demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "sboms" / "finos-deep-sbom-demo"
TIMESTAMP = "2026-06-23T00:00:00Z"


RepoGraph = Dict[str, List[Tuple[str, List[str]]]]


REPOS: RepoGraph = {
    "architecture-as-code": [
        (
            "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.18",
            [
                "pkg:maven/org.springframework/spring-web@5.3.39",
                "pkg:maven/org.springframework/spring-context@5.3.39",
                "pkg:maven/org.springframework/spring-beans@5.3.17",
                "pkg:maven/org.yaml/snakeyaml@1.33",
            ],
        ),
        ("pkg:npm/%40angular/core@16.2.0", ["pkg:npm/axios@1.15.2"]),
        ("pkg:oci/docker.io/library/eclipse-temurin@17-jre", ["pkg:rpm/rhel/xz@5.4.3-1"]),
    ],
    "waltz": [
        (
            "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.7.18",
            [
                "pkg:maven/org.springframework/spring-web@5.3.39",
                "pkg:maven/org.springframework/spring-context@5.3.39",
                "pkg:maven/org.yaml/snakeyaml@1.33",
            ],
        ),
        ("pkg:npm/bootstrap@3.4.1", []),
        ("pkg:oci/docker.io/library/tomcat@9-jre17", ["pkg:rpm/rhel/xz@5.4.3-1"]),
    ],
    "traderX": [
        ("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.2", []),
        ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", []),
        ("pkg:npm/express-rate-limit@8.1.0", []),
        ("pkg:oci/docker.io/library/node@20-bookworm", ["pkg:rpm/rhel/xz@5.4.3-1"]),
    ],
    "open-resource-broker": [
        ("pkg:pypi/fastapi@0.95.0", ["pkg:pypi/requests@2.25.0", "pkg:pypi/urllib3@2.6.3"]),
        ("pkg:pypi/cryptography@46.0.5", []),
        ("pkg:oci/docker.io/library/python@3.11-slim", ["pkg:rpm/rhel/xz@5.4.3-1"]),
    ],
    "ipyregulartable": [
        ("pkg:pypi/jupyterlab@4.0.0", ["pkg:pypi/requests@2.27.1", "pkg:pypi/numpy@1.20.0"]),
        ("pkg:npm/%40jupyterlab/application@4.0.0", ["pkg:npm/bootstrap@3.4.1"]),
    ],
    "TimeBase-CE": [
        ("pkg:maven/io.netty/netty-codec-http2@4.1.99.Final", []),
        ("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.2", []),
        ("pkg:maven/org.apache.activemq/activemq-client@5.17.2", []),
        ("pkg:oci/docker.io/library/eclipse-temurin@21-jre", ["pkg:rpm/rhel/xz@5.4.3-1"]),
    ],
    "FDC3": [
        ("pkg:npm/%40finos/fdc3@2.0.0", ["pkg:npm/axios@1.15.2", "pkg:npm/bootstrap@3.4.1"]),
        ("pkg:npm/express-rate-limit@8.1.0", []),
    ],
    "symphony-bdk-java": [
        (
            "pkg:maven/org.springframework/spring-webmvc@6.1.3",
            ["pkg:maven/org.springframework/spring-beans@5.3.17"],
        ),
        ("pkg:maven/org.bitbucket.b_c/jose4j@0.9.2", []),
        ("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.2", []),
    ],
}


from common import parse_library_id


def split_purl(purl: str) -> Tuple[str, str, str, str]:
    return parse_library_id(purl)


def component_for(purl: str) -> Dict[str, str]:
    namespace, group, name, version = split_purl(purl)
    component_type = "container" if namespace == "oci" else "library"
    component = {
        "type": component_type,
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "scope": "required",
    }
    if group:
        component["group"] = group
    return component


def ordered_components(graph: List[Tuple[str, List[str]]]) -> List[str]:
    out: List[str] = []
    seen = set()
    for direct, children in graph:
        for purl in [direct, *children]:
            if purl not in seen:
                seen.add(purl)
                out.append(purl)
    return out


def dependency_rows(root_ref: str, graph: List[Tuple[str, List[str]]], components: Iterable[str]) -> List[Dict[str, object]]:
    rows = [{"ref": root_ref, "dependsOn": [direct for direct, _children in graph]}]
    child_map = {direct: children for direct, children in graph}
    for purl in components:
        rows.append({"ref": purl, "dependsOn": child_map.get(purl, [])})
    return rows


def write_repo(repo: str, graph: List[Tuple[str, List[str]]]) -> None:
    root_ref = f"pkg:github/finos/{repo}@main"
    components = ordered_components(graph)
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": TIMESTAMP,
            "tools": [{"vendor": "Risk Navigator", "name": "curated-deep-sbom-demo", "version": "0.1.0"}],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": repo,
                "version": "main",
                "externalReferences": [{"type": "vcs", "url": f"https://github.com/finos/{repo}.git"}],
            },
        },
        "components": [component_for(purl) for purl in components],
        "dependencies": dependency_rows(root_ref, graph, components),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / f"{repo}.cdx.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    for stale in OUT_DIR.glob("*.cdx.json"):
        stale.unlink()
    for repo, graph in REPOS.items():
        write_repo(repo, graph)
    print(json.dumps({"out_dir": str(OUT_DIR), "sboms": sorted(p.name for p in OUT_DIR.glob("*.cdx.json"))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

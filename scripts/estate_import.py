#!/usr/bin/env python3
"""Import company software estates across CycloneDX, SPDX, and inventory feeds (#22).

Provides:
- Versioned estate contract (`osera-estate-contract/v1`) and compatibility mapper
  for the Risk Navigator scope dataset (`risk-navigator-scope/v1`).
- Adapters for CycloneDX (1.4-1.6 JSON), SPDX (2.2/2.3 JSON), and company inventory
  feeds (JSON or CSV).
- Explicit separation of `application`, `build`, and `deployment` identities so
  repeated SBOM imports across builds and environments do not inflate application
  or exposure counts while keeping distinct deployments traceable.
- Preservation of full PURLs, vendor/distro/classifier qualifiers, subpaths,
  cryptographic digests, dependency paths, scopes, and observation timestamps.
- Explicit `unknown` dependency classification when dependency graph data is
  absent, preventing graphless SBOMs from producing direct-dependency
  remediation recipes.
- Private company overlay engine (`osera-company-overlay/v1`) for ownership,
  criticality, environment, exposure, runtime constraints, and change windows
  that alters filtering and prioritization without modifying shared core code
  or disclosing private inventory.
"""

from __future__ import annotations

import copy
import csv
import json
import re
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from common import canonical_package_name, canonical_release, make_library_id, parse_library_id, slugify

ESTATE_CONTRACT_SCHEMA_VERSION = "osera-estate-contract/v1"
SCOPE_DATASET_SCHEMA_VERSION = "risk-navigator-scope/v1"
COMPANY_OVERLAY_SCHEMA_VERSION = "osera-company-overlay/v1"

REPACKAGED_VERSION_RE = re.compile(
    r"(?i)(?:[.+_-])(internal|corp|repackaged|vendor|patched|hotfix|custom|redhat|rhel\d*|el\d+|amzn\d+|deb\d+|ubuntu\d+|alpine\d*|fips)(?:$|[.+_-])"
)
VENDOR_DISTRO_QUALIFIER_KEYS = {
    "distro",
    "vendor",
    "repository_url",
    "Classifier",
    "classifier",
    "arch",
    "epoch",
    "upstream",
    "patch_level",
}
AMBIGUOUS_VERSION_TOKENS = {"unspecified", "unknown", "latest", "*", "none", ""}

CRITICALITY_WEIGHTS = {
    "tier-0": 1.6,
    "critical": 1.5,
    "mission-critical": 1.6,
    "tier-1": 1.3,
    "high": 1.25,
    "tier-2": 1.0,
    "medium": 1.0,
    "standard": 1.0,
    "tier-3": 0.75,
    "low": 0.75,
}

EXPOSURE_WEIGHTS = {
    "internet-facing": 1.4,
    "external": 1.4,
    "public": 1.35,
    "partner-facing": 1.2,
    "b2b": 1.2,
    "internal": 1.0,
    "intranet": 1.0,
    "air-gapped": 0.7,
    "isolated": 0.7,
}

ENVIRONMENT_WEIGHTS = {
    "production": 1.25,
    "prod": 1.25,
    "dr": 1.15,
    "staging": 0.9,
    "uat": 0.9,
    "preprod": 0.95,
    "qa": 0.8,
    "test": 0.7,
    "dev": 0.65,
    "development": 0.65,
    "sandbox": 0.55,
}

EFFORT_RANK = {
    "PATCH": 1,
    "MINOR": 2,
    "MAJOR": 3,
    "DEAD_END": 4,
    "UNKNOWN": 5,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_iso_timestamp(value: Any, fallback: str = "") -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    raw = value.strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except ValueError:
        return raw


def normalize_version_text(raw: str) -> str:
    value = str(raw or "").strip().strip('"').strip("'")
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
    if re.match(r"^[vV](?=\d)", value):
        value = value[1:]
    return value or "unspecified"


def is_unpinned_or_range_version(raw: str) -> bool:
    text = str(raw or "").strip()
    if not text or text.lower() in AMBIGUOUS_VERSION_TOKENS:
        return True
    if any(op in text for op in ("^", "~", ">", "<", "*", "||", " - ")) or text.startswith("${"):
        return True
    if re.match(r"^\d+\.(?:x|X|\*)(?:\b|$)", text) or re.match(r"^\d+\.\d+\.(?:x|X|\*)(?:\b|$)", text):
        return True
    return False


def parse_purl_rich(
    purl: str,
    fallback: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Parse a PURL while preserving full qualifiers, subpaths, and repackaging signals."""

    fb = fallback if isinstance(fallback, dict) else {}
    raw = str(purl or "").strip()
    if not raw.startswith("pkg:"):
        return {
            "valid": False,
            "full_purl": raw,
            "base_purl": "",
            "namespace": "",
            "meta": "",
            "proj": "",
            "release": "",
            "raw_release": "",
            "qualifiers": {},
            "subpath": "",
            "error": "Not a valid pkg: URL" if raw else "Missing PURL",
        }

    body = raw[4:]
    subpath = ""
    if "#" in body:
        body, subpath_raw = body.split("#", 1)
        subpath = urllib.parse.unquote(subpath_raw.strip("/"))

    qualifiers: Dict[str, str] = {}
    if "?" in body:
        body, query_raw = body.split("?", 1)
        for pair in query_raw.split("&"):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[urllib.parse.unquote(k.strip())] = urllib.parse.unquote(v.strip())
            else:
                qualifiers[urllib.parse.unquote(pair.strip())] = ""

    raw_release = "unspecified"
    if "@" in body:
        body, raw_release = body.rsplit("@", 1)
        raw_release = urllib.parse.unquote(raw_release.strip())

    if "/" in body:
        namespace, rest = body.split("/", 1)
    else:
        namespace, rest = body, ""

    namespace = urllib.parse.unquote(namespace).strip().lower()
    rest_parts = [urllib.parse.unquote(part) for part in rest.split("/") if part]

    meta = ""
    proj = ""
    if namespace == "maven" and len(rest_parts) >= 2:
        meta = rest_parts[0]
        proj = rest_parts[1]
    elif namespace == "npm" and len(rest_parts) >= 2 and rest_parts[0].startswith("@"):
        meta = rest_parts[0]
        proj = rest_parts[1]
    elif len(rest_parts) >= 2:
        meta = "/".join(rest_parts[:-1])
        proj = rest_parts[-1]
    elif rest_parts:
        proj = rest_parts[0]
        if namespace == "generic":
            meta = "unknown"

    if not proj:
        fb_name = str(fb.get("name") or "").strip()
        fb_group = str(fb.get("group") or "").strip()
        if fb_name:
            proj = fb_name
            meta = fb_group or ("unknown" if namespace == "generic" else "")

    if not namespace or not proj:
        return {
            "valid": False,
            "full_purl": raw,
            "raw_purl": raw,
            "base_purl": "",
            "namespace": namespace,
            "meta": meta,
            "proj": proj,
            "release": "",
            "raw_release": raw_release,
            "qualifiers": qualifiers,
            "subpath": subpath,
            "error": f"Incomplete coordinate in PURL: {raw}",
        }

    normalized_release = normalize_version_text(raw_release)
    purl_meta = "" if (namespace == "generic" and meta == "unknown" and len(rest_parts) == 1) else meta
    coord_path = "/".join(
        urllib.parse.quote(part, safe="@/")
        for part in ([purl_meta, proj] if purl_meta else [proj])
    )
    base_purl = f"pkg:{namespace}/{coord_path}@{urllib.parse.quote(normalized_release, safe='')}"
    full_purl = base_purl
    if qualifiers:
        q_str = "&".join(
            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe=':/')}"
            for k, v in sorted(qualifiers.items())
        )
        full_purl = f"{full_purl}?{q_str}"
    if subpath:
        full_purl = f"{full_purl}#{urllib.parse.quote(subpath, safe='/')}"

    return {
        "valid": True,
        "full_purl": full_purl,
        "raw_purl": raw,
        "base_purl": base_purl,
        "namespace": namespace,
        "meta": meta,
        "proj": proj,
        "release": normalized_release,
        "raw_release": raw_release,
        "qualifiers": qualifiers,
        "subpath": subpath,
        "error": None,
    }


def _canonical_digest_algorithm(raw_alg: str) -> str:
    alg = str(raw_alg or "").strip().upper().replace("_", "-")
    mapping = {
        "SHA256": "SHA-256",
        "SHA-256": "SHA-256",
        "SHA512": "SHA-512",
        "SHA-512": "SHA-512",
        "SHA384": "SHA-384",
        "SHA-384": "SHA-384",
        "SHA1": "SHA-1",
        "SHA-1": "SHA-1",
        "MD5": "MD5",
    }
    return mapping.get(alg, alg or "SHA-256")


def normalize_digests(raw_hashes: Any) -> List[Dict[str, str]]:
    """Normalize CycloneDX `hashes`, SPDX `checksums`, or string digest lists into structured `{algorithm, value}` records."""

    out: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def _add(alg_raw: str, val_raw: str) -> None:
        alg = _canonical_digest_algorithm(alg_raw)
        val = str(val_raw or "").strip().lower()
        if not val:
            return
        key = (alg, val)
        if key not in seen:
            seen.add(key)
            out.append({"algorithm": alg, "value": val})

    if isinstance(raw_hashes, str) and raw_hashes.strip():
        raw_str = raw_hashes.strip()
        if ":" in raw_str:
            a, v = raw_str.split(":", 1)
            _add(a, v)
        else:
            _add("SHA-256", raw_str)
    elif isinstance(raw_hashes, dict):
        for alg, val in sorted(raw_hashes.items()):
            if val:
                _add(str(alg), str(val))
    elif isinstance(raw_hashes, list):
        for item in raw_hashes:
            if isinstance(item, str) and item.strip():
                val = item.strip()
                if ":" in val:
                    a, v = val.split(":", 1)
                    _add(a, v)
                else:
                    _add("SHA-256", val)
            elif isinstance(item, dict):
                alg = str(item.get("alg") or item.get("algorithm") or "").strip()
                content = str(item.get("content") or item.get("checksumValue") or item.get("value") or "").strip()
                if alg and content:
                    _add(alg, content)
    return out


def classify_scope_qualifier(raw_scope: str) -> str:
    scope = str(raw_scope or "").strip().lower()
    if scope in {"excluded", "optional", "build", "provided", "compile-only"}:
        return "build"
    if scope in {"test", "development", "dev", "testing"}:
        return "test"
    return "runtime"


def detect_identity_status(
    *,
    explicit_purl: str,
    parsed_purl: Dict[str, Any],
    raw_version: str,
    supplier_or_origin: str = "",
) -> Tuple[str, bool, List[str]]:
    """Determine identity certainty (`exact`, `qualified_or_repackaged`, `ambiguous`) and reasons."""

    reasons: List[str] = []
    is_repackaged = False

    if not explicit_purl:
        reasons.append("Missing explicit PURL; coordinates synthesized from component group/name.")
    elif not parsed_purl.get("valid"):
        reasons.append(str(parsed_purl.get("error") or "Invalid PURL syntax"))

    if is_unpinned_or_range_version(raw_version):
        reasons.append(f"Ambiguous or unpinned version expression: {raw_version or 'unspecified'}")

    ns = str(parsed_purl.get("namespace") or "").lower()
    meta = str(parsed_purl.get("meta") or "").lower()
    if ns == "generic" and meta in {"", "unknown"}:
        reasons.append("Ambiguous generic ecosystem identity with missing vendor/group namespace.")

    qualifiers: Dict[str, str] = parsed_purl.get("qualifiers") or {}
    distro = qualifiers.get("distro") or qualifiers.get("os") or ""
    vendor = qualifiers.get("vendor") or qualifiers.get("supplier") or ""
    repo_url = qualifiers.get("repository_url") or ""
    classifier = qualifiers.get("classifier") or ""

    if distro:
        is_repackaged = True
        reasons.append(f"Distro qualifier preserved: distro={distro}")
    if vendor:
        is_repackaged = True
        reasons.append(f"Vendor qualifier preserved: vendor={vendor}")
    if repo_url:
        is_repackaged = True
        reasons.append(f"Custom repository qualifier preserved (internally repackaged): repository_url={repo_url}")
    if classifier:
        reasons.append(f"Artifact classifier qualifier preserved: classifier={classifier}")
    if parsed_purl.get("subpath"):
        reasons.append(f"Artifact subpath preserved: #{parsed_purl['subpath']}")

    release = str(parsed_purl.get("release") or raw_version or "")
    if REPACKAGED_VERSION_RE.search(release):
        is_repackaged = True
        reasons.append(f"Vendor/distro or internally repackaged version marker in '{release}'")

    supplier_lower = str(supplier_or_origin or "").strip().lower()
    if supplier_lower and any(tok in supplier_lower for tok in ("internal", "repackaged", "corporate", "in-house", "private")):
        is_repackaged = True
        reasons.append(f"Internal/repackaged supplier metadata (internally repackaged): {supplier_or_origin}")

    ambiguous = (
        (not explicit_purl)
        or (not parsed_purl.get("valid"))
        or is_unpinned_or_range_version(raw_version)
        or (ns == "generic" and meta in {"", "unknown"})
    )
    if ambiguous:
        status = "ambiguous"
    elif is_repackaged or bool(qualifiers) or bool(parsed_purl.get("subpath")):
        status = "qualified_or_repackaged"
    else:
        status = "exact"

    return status, is_repackaged, reasons


def compute_dependency_paths(
    root_ref: str,
    adjacency: Dict[str, List[str]],
    label_by_ref: Dict[str, str],
    max_depth: int = 8,
) -> Tuple[Set[str], Dict[str, str], Dict[str, List[List[str]]]]:
    """Compute direct refs, first parent ref, and full dependency paths via BFS from root_ref."""

    direct_refs: Set[str] = set()
    parent_by_child: Dict[str, str] = {}
    paths_by_ref: Dict[str, List[List[str]]] = {}

    if not root_ref or root_ref not in adjacency:
        # Even if root_ref is absent from adjacency keys, check if other nodes have edges
        for parent, children in adjacency.items():
            for child in children:
                if child and child != root_ref:
                    parent_by_child.setdefault(child, parent)
        return direct_refs, parent_by_child, paths_by_ref

    root_label = label_by_ref.get(root_ref, root_ref)
    for child in adjacency.get(root_ref, []):
        if child and child != root_ref:
            direct_refs.add(child)
            parent_by_child.setdefault(child, root_ref)

    queue: deque[Tuple[str, List[str], Set[str]]] = deque([(root_ref, [root_label], {root_ref})])
    while queue:
        current_ref, current_path, visited = queue.popleft()
        if len(current_path) > max_depth:
            continue
        for child_ref in adjacency.get(current_ref, []):
            if not child_ref or child_ref in visited:
                continue
            parent_by_child.setdefault(child_ref, current_ref)
            child_label = label_by_ref.get(child_ref, child_ref)
            next_path = current_path + [child_label]
            bucket = paths_by_ref.setdefault(child_ref, [])
            if next_path not in bucket and len(bucket) < 5:
                bucket.append(next_path)
            queue.append((child_ref, next_path, visited | {child_ref}))

    # Also capture any disconnected subgraphs in `adjacency` not reachable from `root_ref`
    for parent, children in adjacency.items():
        for child in children:
            if child and child != root_ref:
                parent_by_child.setdefault(child, parent)
                if child not in paths_by_ref:
                    p_label = label_by_ref.get(parent, parent)
                    c_label = label_by_ref.get(child, child)
                    paths_by_ref[child] = [[root_label, p_label, c_label]]

    return direct_refs, parent_by_child, paths_by_ref


def _extract_properties_dict(props: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(props, list):
        for item in props:
            if isinstance(item, dict) and item.get("name"):
                raw_k = str(item["name"]).strip()
                val = str(item.get("value") or "").strip()
                out[raw_k] = val
                for prefix in ("osera:", "cdx:", "org:"):
                    if raw_k.lower().startswith(prefix):
                        out[raw_k[len(prefix):]] = val
    elif isinstance(props, dict):
        for k, v in props.items():
            raw_k = str(k).strip()
            val = str(v or "").strip()
            out[raw_k] = val
            for prefix in ("osera:", "cdx:", "org:"):
                if raw_k.lower().startswith(prefix):
                    out[raw_k[len(prefix):]] = val
    return out


def _derive_application_identity(
    *,
    explicit_app_id: str = "",
    vcs_url: str = "",
    comp_group: str = "",
    comp_name: str = "",
    comp_version: str = "",
    fallback_stem: str = "application",
    department: str = "SBOM Scan",
    eonid: str = "",
    tai_system: str = "",
) -> Dict[str, str]:
    """Derive a canonical application identity independent of build or deployment IDs."""

    cleaned_stem = re.sub(
        r"(?i)[._-](build|deploy|deployment|prod|production|staging|uat|dev|qa|us-east|eu-west|ap-south|v?\d+(?:\.\d+)*)[A-Za-z0-9._-]*$",
        "",
        fallback_stem,
    ).strip("._-") or fallback_stem

    project_ref = ""
    owner = "imported"
    repo_name = slugify(comp_name or cleaned_stem)
    if "/" in comp_name and not comp_group:
        c_parts = [p for p in comp_name.split("/") if p]
        if len(c_parts) == 2:
            owner, repo_name = slugify(c_parts[0]), slugify(c_parts[1])
    namespace = "github"

    if vcs_url:
        cleaned_vcs = vcs_url.removesuffix(".git").strip("/")
        if "github.com/" in cleaned_vcs:
            suffix = cleaned_vcs.split("github.com/", 1)[1].strip("/")
            parts = [p for p in suffix.split("/") if p]
            if len(parts) >= 2:
                owner, repo_name = parts[0], parts[1]
                project_ref = f"github/{owner}/{repo_name}"
        else:
            project_ref = cleaned_vcs

    if explicit_app_id:
        app_id = explicit_app_id.strip()
        if "|" in app_id:
            parts = app_id.split("|")
            if len(parts) >= 3:
                namespace, owner, repo_name = parts[0], parts[1], parts[2]
        else:
            repo_name = slugify(app_id)
            owner = slugify(comp_group) if comp_group else owner
            app_id = f"{namespace}|{owner}|{repo_name}"
    else:
        if comp_group and owner == "imported":
            owner = slugify(comp_group)
        if comp_version and comp_version not in {"0.0.0", "unspecified"}:
            app_id = f"{namespace}|{owner}|{repo_name}|{comp_version}"
        else:
            app_id = f"{namespace}|{owner}|{repo_name}"

    if not project_ref:
        project_ref = f"{namespace}/{owner}/{repo_name}"

    return {
        "application_id": app_id,
        "namespace": namespace,
        "meta": owner,
        "proj": repo_name,
        "name": comp_name or repo_name,
        "project_ref": project_ref,
        "department": department or "SBOM Scan",
        "eonid": eonid or "",
        "tai_system": tai_system or (comp_name or repo_name),
    }


def parse_cyclonedx_document(
    payload: Dict[str, Any],
    source_path: str = "memory.cdx.json",
) -> Dict[str, Any]:
    """Adapt a CycloneDX (1.4-1.6) JSON document into a normalized build/deployment observation."""

    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    component = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    props = {
        **_extract_properties_dict(metadata.get("properties")),
        **_extract_properties_dict(component.get("properties")),
    }

    observed_at = normalize_iso_timestamp(
        metadata.get("timestamp") or props.get("observed_at") or props.get("timestamp"),
        fallback=now_iso(),
    )

    vcs_url = ""
    for ref in component.get("externalReferences") or []:
        if isinstance(ref, dict) and str(ref.get("type") or "").lower() == "vcs":
            vcs_url = str(ref.get("url") or "").strip()
            break

    comp_name = str(component.get("name") or Path(source_path).stem).strip()
    comp_group = str(component.get("group") or props.get("group") or props.get("business_unit") or "").strip()
    comp_version = str(component.get("version") or props.get("build_version") or "0.0.0").strip()
    explicit_app_id = str(
        props.get("application_id")
        or props.get("app_id")
        or props.get("cdx:application:id")
        or component.get("application_id")
        or ""
    ).strip()
    department = str(
        props.get("department")
        or props.get("business_unit")
        or props.get("org:department")
        or "SBOM Scan"
    ).strip()
    eonid = str(props.get("eonid") or props.get("asset_id") or "").strip()
    tai_system = str(props.get("tai_system") or comp_name).strip()

    app_identity = _derive_application_identity(
        explicit_app_id=explicit_app_id,
        vcs_url=vcs_url,
        comp_group=comp_group,
        comp_name=comp_name,
        fallback_stem=Path(source_path).stem,
        department=department,
        eonid=eonid,
        tai_system=tai_system,
    )

    serial_number = str(payload.get("serialNumber") or "").strip()
    bom_version = str(payload.get("version") or "1").strip()
    build_id = str(
        props.get("build_id")
        or props.get("ci:build_id")
        or (f"{serial_number}#v{bom_version}" if serial_number else "")
        or f"build:{app_identity['proj']}:{comp_version}:{Path(source_path).stem}"
    ).strip()
    commit_sha = str(props.get("commit_sha") or props.get("git:commit") or "").strip()

    environment = str(
        props.get("environment")
        or props.get("deployment:environment")
        or props.get("env")
        or "build"
    ).strip().lower()
    region = str(props.get("region") or props.get("deployment:region") or "global").strip()
    deployment_id = str(
        props.get("deployment_id")
        or props.get("deployment:id")
        or f"deploy:{app_identity['proj']}:{environment}:{region}:{build_id}"
    ).strip()

    root_ref = str(component.get("bom-ref") or "").strip()
    raw_components = payload.get("components") if isinstance(payload.get("components"), list) else []
    components = [c for c in raw_components if isinstance(c, dict)]

    # Build adjacency graph from CycloneDX `dependencies`
    deps_raw = payload.get("dependencies")
    has_deps_array = isinstance(deps_raw, list) and len(deps_raw) > 0
    adjacency: Dict[str, List[str]] = {}
    non_empty_edges = 0
    if isinstance(deps_raw, list):
        for row in deps_raw:
            if not isinstance(row, dict):
                continue
            ref = str(row.get("ref") or "").strip()
            if not ref:
                continue
            children = [
                str(c).strip()
                for c in (row.get("dependsOn") or [])
                if isinstance(c, (str, int)) and str(c).strip()
            ]
            adjacency[ref] = children
            non_empty_edges += len(children)

    graph_available = bool(has_deps_array and non_empty_edges > 0)

    label_by_ref: Dict[str, str] = {}
    if root_ref:
        label_by_ref[root_ref] = app_identity["application_id"]

    parsed_by_ref: Dict[str, Dict[str, Any]] = {}
    mapped_observations: List[Dict[str, Any]] = []
    unmapped_records: List[Dict[str, Any]] = []

    for idx, comp in enumerate(components):
        ref = str(comp.get("bom-ref") or comp.get("purl") or f"component-{idx}").strip()
        raw_purl = str(comp.get("purl") or "").strip()
        raw_name = str(comp.get("name") or "").strip()
        raw_group = str(comp.get("group") or "").strip()
        raw_ver = str(comp.get("version") or "").strip()
        comp_props = _extract_properties_dict(comp.get("properties"))

        if raw_purl:
            parsed = parse_purl_rich(raw_purl, comp)
        elif raw_name:
            synth_ns = str(comp_props.get("ecosystem") or ("maven" if raw_group else "generic")).strip().lower()
            coord = f"{raw_group}/{raw_name}" if raw_group else raw_name
            synth_purl = f"pkg:{synth_ns}/{coord}@{raw_ver or 'unspecified'}"
            parsed = parse_purl_rich(synth_purl, comp)
        else:
            parsed = {"valid": False, "error": "Component missing both purl and name"}

        if not parsed.get("valid") or not parsed.get("namespace") or not parsed.get("proj"):
            unmapped_records.append(
                {
                    "source_path": str(source_path),
                    "source_format": "cyclonedx",
                    "application_id": app_identity["application_id"],
                    "build_id": build_id,
                    "raw_identifier": raw_purl or ref,
                    "name": raw_name,
                    "version": raw_ver,
                    "reason": str(parsed.get("error") or "Missing package coordinates"),
                }
            )
            continue

        # Reject unresolvable template expressions like `${spring.version}` from library_id mapping
        if parsed["release"].startswith("${") or parsed["release"] == "unspecified":
            unmapped_records.append(
                {
                    "source_path": str(source_path),
                    "source_format": "cyclonedx",
                    "application_id": app_identity["application_id"],
                    "build_id": build_id,
                    "raw_identifier": raw_purl or ref,
                    "name": raw_name or parsed["proj"],
                    "version": raw_ver or parsed["release"],
                    "reason": f"Unresolved or unspecified component version: {raw_ver or parsed['release']}",
                }
            )
            continue

        canon_rel = canonical_release(parsed["namespace"], parsed["release"])
        library_id = make_library_id(parsed["namespace"], parsed["meta"], parsed["proj"], canon_rel)
        label_by_ref[ref] = library_id
        parsed_by_ref[ref] = {
            "comp": comp,
            "parsed": parsed,
            "library_id": library_id,
            "raw_purl": raw_purl,
            "raw_ver": raw_ver or parsed["raw_release"],
            "comp_props": comp_props,
        }

    direct_refs, parent_by_child, paths_by_ref = (
        compute_dependency_paths(root_ref, adjacency, label_by_ref)
        if graph_available
        else (set(), {}, {})
    )

    for ref, info in parsed_by_ref.items():
        comp = info["comp"]
        parsed = info["parsed"]
        library_id = info["library_id"]
        comp_props = info["comp_props"]

        raw_scope = str(comp.get("scope") or comp_props.get("scope") or "required").strip().lower()
        qualifier = classify_scope_qualifier(raw_scope)

        # Explicit dependency classification: never assume direct when graph data is absent!
        explicit_rel = str(comp_props.get("dependency_classification") or "").strip().lower()
        parent_ref = parent_by_child.get(ref, "")
        parent_library_id = ""
        if explicit_rel in {"direct", "transitive", "unknown"}:
            dep_classification = explicit_rel
            if dep_classification == "transitive" and parent_ref in parsed_by_ref:
                parent_library_id = parsed_by_ref[parent_ref]["library_id"]
        elif not graph_available:
            dep_classification = "unknown"
        elif ref in direct_refs or (root_ref and parent_ref == root_ref):
            dep_classification = "direct"
        elif ref in parent_by_child or ref in paths_by_ref:
            dep_classification = "transitive"
            if parent_ref in parsed_by_ref:
                parent_library_id = parsed_by_ref[parent_ref]["library_id"]
        else:
            # Graph exists for the BOM, but this component is an orphan not referenced in `dependencies`
            dep_classification = "unknown"

        supplier_obj = comp.get("supplier") or comp.get("publisher") or comp.get("author") or ""
        if isinstance(supplier_obj, dict):
            supplier_str = str(supplier_obj.get("name") or "").strip()
        else:
            supplier_str = str(supplier_obj or "").strip()

        identity_status, is_repackaged, uncertain_reasons = detect_identity_status(
            explicit_purl=info["raw_purl"],
            parsed_purl=parsed,
            raw_version=info["raw_ver"],
            supplier_or_origin=supplier_str,
        )
        if dep_classification == "unknown":
            uncertain_reasons = list(uncertain_reasons) + [
                "Dependency graph relationship absent; classified as 'unknown' rather than direct."
            ]

        digests = normalize_digests(comp.get("hashes"))
        dep_paths = paths_by_ref.get(ref, [])
        if not dep_paths and dep_classification == "direct":
            root_label = label_by_ref.get(root_ref, app_identity["application_id"])
            dep_paths = [[root_label, library_id]]

        mapped_observations.append(
            {
                "library_id": library_id,
                "purl": parsed["full_purl"],
                "raw_purl": parsed.get("raw_purl") or parsed["full_purl"],
                "base_purl": parsed["base_purl"],
                "namespace": parsed["namespace"],
                "meta": parsed["meta"],
                "proj": parsed["proj"],
                "release": canonical_release(parsed["namespace"], parsed["release"]),
                "qualifiers": parsed["qualifiers"],
                "subpath": parsed["subpath"],
                "digests": digests,
                "scope": raw_scope,
                "qualifier": qualifier,
                "dependency_classification": dep_classification,
                "direct": 1 if dep_classification == "direct" else (0 if dep_classification == "transitive" else None),
                "parent_id": parent_library_id if dep_classification == "transitive" else "",
                "dependency_paths": dep_paths,
                "observed_at": observed_at,
                "build_id": build_id,
                "deployment_id": deployment_id,
                "environment": environment,
                "supplier": supplier_str,
                "identity_status": identity_status,
                "is_repackaged": is_repackaged,
                "uncertain_match_reasons": uncertain_reasons,
            }
        )

    return {
        "source_format": "cyclonedx",
        "source_path": str(source_path),
        "application": app_identity,
        "build": {
            "build_id": build_id,
            "version": comp_version,
            "commit_sha": commit_sha,
            "bom_serial_number": serial_number,
            "source_format": "cyclonedx",
            "source_path": str(source_path),
            "graph_available": graph_available,
            "observed_at": observed_at,
        },
        "deployment": {
            "deployment_id": deployment_id,
            "environment": environment,
            "region": region,
            "build_id": build_id,
            "deployed_at": observed_at,
        },
        "graph_available": graph_available,
        "components_total_observed": len(components),
        "observations": mapped_observations,
        "unmapped_records": unmapped_records,
    }


def parse_spdx_document(
    payload: Dict[str, Any],
    source_path: str = "memory.spdx.json",
) -> Dict[str, Any]:
    """Adapt an SPDX (2.2 / 2.3) JSON document into a normalized build/deployment observation."""

    creation_info = payload.get("creationInfo") if isinstance(payload.get("creationInfo"), dict) else {}
    observed_at = normalize_iso_timestamp(creation_info.get("created"), fallback=now_iso())
    doc_name = str(payload.get("name") or Path(source_path).stem).strip()
    doc_namespace = str(payload.get("documentNamespace") or "").strip()

    raw_packages = payload.get("packages") if isinstance(payload.get("packages"), list) else []
    packages = [p for p in raw_packages if isinstance(p, dict)]
    relationships = payload.get("relationships") if isinstance(payload.get("relationships"), list) else []

    describes: Set[str] = set()
    for d in payload.get("documentDescribes") or []:
        if isinstance(d, str) and d.strip():
            describes.add(d.strip())
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        if str(rel.get("relationshipType") or "").upper() == "DESCRIBES":
            target = str(rel.get("relatedSpdxElement") or "").strip()
            if target:
                describes.add(target)

    pkg_by_spdx_id: Dict[str, Dict[str, Any]] = {
        str(p.get("SPDXID") or "").strip(): p
        for p in packages
        if str(p.get("SPDXID") or "").strip()
    }

    root_spdx_id = next(iter(sorted(describes)), "")
    if not root_spdx_id:
        for sid, p in pkg_by_spdx_id.items():
            if str(p.get("primaryPackagePurpose") or "").upper() in {"APPLICATION", "CONTAINER", "SERVICE"}:
                root_spdx_id = sid
                break
    root_pkg = pkg_by_spdx_id.get(root_spdx_id, {})

    app_name = str(root_pkg.get("name") or doc_name).strip()
    app_version = str(root_pkg.get("versionInfo") or "0.0.0").strip()
    vcs_url = str(root_pkg.get("downloadLocation") or root_pkg.get("DownloadLocation") or "").strip()
    if vcs_url in {"NOASSERTION", "NONE"}:
        vcs_url = ""

    # Check annotations or comment for custom metadata (application_id, environment, build_id)
    meta_kv: Dict[str, str] = {}
    for comment_src in (payload.get("comment"), creation_info.get("comment"), root_pkg.get("comment")):
        if isinstance(comment_src, str) and comment_src.strip():
            for token in re.split(r"[;,\n]", comment_src):
                if "=" in token:
                    k, v = token.split("=", 1)
                    meta_kv[k.strip().lower()] = v.strip()

    app_identity = _derive_application_identity(
        explicit_app_id=meta_kv.get("application_id") or meta_kv.get("app_id") or "",
        vcs_url=vcs_url,
        comp_group=meta_kv.get("business_unit", ""),
        comp_name=app_name,
        comp_version=app_version,
        fallback_stem=Path(source_path).stem,
        department=meta_kv.get("department") or meta_kv.get("business_unit") or "SBOM Scan",
        eonid=meta_kv.get("eonid", ""),
        tai_system=meta_kv.get("tai_system", app_name),
    )

    build_id = meta_kv.get("build_id") or (doc_namespace if doc_namespace else f"spdx:{app_identity['proj']}:{app_version}")
    environment = (meta_kv.get("environment") or meta_kv.get("env") or "build").lower()
    region = meta_kv.get("region") or "global"
    deployment_id = meta_kv.get("deployment_id") or f"deploy:{app_identity['proj']}:{environment}:{region}:{build_id}"

    # Build adjacency graph from SPDX relationships
    adjacency: Dict[str, List[str]] = {}
    dep_rel_count = 0
    dev_spdx_ids: Set[str] = set()
    build_spdx_ids: Set[str] = set()

    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        rel_type = str(rel.get("relationshipType") or "").upper()
        left = str(rel.get("spdxElementId") or "").strip()
        right = str(rel.get("relatedSpdxElement") or "").strip()
        if not left or not right or left == "SPDXRef-DOCUMENT":
            continue
        if rel_type in {"DEPENDS_ON", "DYNAMIC_LINK", "STATIC_LINK", "CONTAINS"}:
            adjacency.setdefault(left, []).append(right)
            dep_rel_count += 1
        elif rel_type in {"DEPENDENCY_OF", "CONTAINED_BY"}:
            adjacency.setdefault(right, []).append(left)
            dep_rel_count += 1
        elif rel_type in {"DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF"}:
            dev_spdx_ids.add(left)
            adjacency.setdefault(right, []).append(left)
            dep_rel_count += 1
        elif rel_type in {"BUILD_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF"}:
            build_spdx_ids.add(left)
            adjacency.setdefault(right, []).append(left)
            dep_rel_count += 1

    graph_available = dep_rel_count > 0

    label_by_ref: Dict[str, str] = {}
    if root_spdx_id:
        label_by_ref[root_spdx_id] = app_identity["application_id"]

    parsed_by_ref: Dict[str, Dict[str, Any]] = {}
    unmapped_records: List[Dict[str, Any]] = []
    component_packages = [p for p in packages if str(p.get("SPDXID") or "").strip() != root_spdx_id]

    for idx, pkg in enumerate(component_packages):
        spdx_id = str(pkg.get("SPDXID") or f"SPDXRef-Pkg-{idx}").strip()
        pkg_name = str(pkg.get("name") or "").strip()
        pkg_ver = str(pkg.get("versionInfo") or "").strip()
        raw_purl = ""
        for ext in pkg.get("externalRefs") or []:
            if isinstance(ext, dict) and str(ext.get("referenceType") or "").lower() == "purl":
                raw_purl = str(ext.get("referenceLocator") or "").strip()
                if raw_purl:
                    break

        if raw_purl:
            parsed = parse_purl_rich(raw_purl, {"name": pkg_name, "version": pkg_ver})
        elif pkg_name:
            if ":" in pkg_name and "/" not in pkg_name:
                grp, art = pkg_name.split(":", 1)
                synth = f"pkg:maven/{grp}/{art}@{pkg_ver or 'unspecified'}"
            else:
                synth = f"pkg:generic/{pkg_name}@{pkg_ver or 'unspecified'}"
            parsed = parse_purl_rich(synth, {"name": pkg_name, "version": pkg_ver})
        else:
            parsed = {"valid": False, "error": "SPDX package missing both PURL externalRef and name"}

        if not parsed.get("valid") or not parsed.get("namespace") or not parsed.get("proj"):
            unmapped_records.append(
                {
                    "source_path": str(source_path),
                    "source_format": "spdx",
                    "application_id": app_identity["application_id"],
                    "build_id": build_id,
                    "raw_identifier": raw_purl or spdx_id,
                    "name": pkg_name,
                    "version": pkg_ver,
                    "reason": str(parsed.get("error") or "Unmapped SPDX package"),
                }
            )
            continue

        if parsed["release"].startswith("${") or parsed["release"] == "unspecified":
            unmapped_records.append(
                {
                    "source_path": str(source_path),
                    "source_format": "spdx",
                    "application_id": app_identity["application_id"],
                    "build_id": build_id,
                    "raw_identifier": raw_purl or spdx_id,
                    "name": pkg_name,
                    "version": pkg_ver,
                    "reason": f"Unspecified or template version in SPDX package: {pkg_ver or parsed['release']}",
                }
            )
            continue

        canon_rel = canonical_release(parsed["namespace"], parsed["release"])
        library_id = make_library_id(parsed["namespace"], parsed["meta"], parsed["proj"], canon_rel)
        label_by_ref[spdx_id] = library_id
        parsed_by_ref[spdx_id] = {
            "pkg": pkg,
            "parsed": parsed,
            "library_id": library_id,
            "raw_purl": raw_purl,
            "raw_ver": pkg_ver or parsed["raw_release"],
        }

    direct_refs, parent_by_child, paths_by_ref = (
        compute_dependency_paths(root_spdx_id, adjacency, label_by_ref)
        if graph_available
        else (set(), {}, {})
    )

    mapped_observations: List[Dict[str, Any]] = []
    for spdx_id, info in parsed_by_ref.items():
        pkg = info["pkg"]
        parsed = info["parsed"]
        library_id = info["library_id"]

        if spdx_id in dev_spdx_ids:
            raw_scope, qualifier = "test", "test"
        elif spdx_id in build_spdx_ids:
            raw_scope, qualifier = "optional", "build"
        else:
            raw_scope, qualifier = "required", "runtime"

        parent_ref = parent_by_child.get(spdx_id, "")
        parent_library_id = ""
        if not graph_available:
            dep_classification = "unknown"
        elif spdx_id in direct_refs or (root_spdx_id and parent_ref == root_spdx_id):
            dep_classification = "direct"
        elif spdx_id in parent_by_child or spdx_id in paths_by_ref:
            dep_classification = "transitive"
            if parent_ref in parsed_by_ref:
                parent_library_id = parsed_by_ref[parent_ref]["library_id"]
        else:
            dep_classification = "unknown"

        supplier = str(pkg.get("supplier") or pkg.get("originator") or "").strip()
        if supplier in {"NOASSERTION", "NONE"}:
            supplier = ""

        identity_status, is_repackaged, uncertain_reasons = detect_identity_status(
            explicit_purl=info["raw_purl"],
            parsed_purl=parsed,
            raw_version=info["raw_ver"],
            supplier_or_origin=supplier,
        )
        if dep_classification == "unknown":
            uncertain_reasons = list(uncertain_reasons) + [
                "Dependency graph relationship absent in SPDX relationships; classified as 'unknown'."
            ]

        digests = normalize_digests(pkg.get("checksums"))
        dep_paths = paths_by_ref.get(spdx_id, [])
        if not dep_paths and dep_classification == "direct":
            dep_paths = [[app_identity["application_id"], library_id]]

        mapped_observations.append(
            {
                "library_id": library_id,
                "purl": parsed["full_purl"],
                "raw_purl": parsed.get("raw_purl") or parsed["full_purl"],
                "base_purl": parsed["base_purl"],
                "namespace": parsed["namespace"],
                "meta": parsed["meta"],
                "proj": parsed["proj"],
                "release": canonical_release(parsed["namespace"], parsed["release"]),
                "qualifiers": parsed["qualifiers"],
                "subpath": parsed["subpath"],
                "digests": digests,
                "scope": raw_scope,
                "qualifier": qualifier,
                "dependency_classification": dep_classification,
                "direct": 1 if dep_classification == "direct" else (0 if dep_classification == "transitive" else None),
                "parent_id": parent_library_id if dep_classification == "transitive" else "",
                "dependency_paths": dep_paths,
                "observed_at": observed_at,
                "build_id": build_id,
                "deployment_id": deployment_id,
                "environment": environment,
                "supplier": supplier,
                "identity_status": identity_status,
                "is_repackaged": is_repackaged,
                "uncertain_match_reasons": uncertain_reasons,
            }
        )

    return {
        "source_format": "spdx",
        "source_path": str(source_path),
        "application": app_identity,
        "build": {
            "build_id": build_id,
            "version": app_version,
            "commit_sha": meta_kv.get("commit_sha", ""),
            "bom_serial_number": doc_namespace,
            "source_format": "spdx",
            "source_path": str(source_path),
            "graph_available": graph_available,
            "observed_at": observed_at,
        },
        "deployment": {
            "deployment_id": deployment_id,
            "environment": environment,
            "region": region,
            "build_id": build_id,
            "deployed_at": observed_at,
        },
        "graph_available": graph_available,
        "components_total_observed": len(component_packages),
        "observations": mapped_observations,
        "unmapped_records": unmapped_records,
    }


def parse_company_inventory_feed(
    payload: Any,
    source_path: str = "company-inventory.json",
) -> List[Dict[str, Any]]:
    """Adapt a company inventory feed (JSON object/list or CSV rows) into build/deployment observations."""

    records: List[Dict[str, Any]] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("applications"), list):
            for app in payload["applications"]:
                if not isinstance(app, dict):
                    continue
                app_id = str(app.get("application_id") or app.get("app_id") or app.get("id") or "").strip()
                app_name = str(app.get("name") or app_id or "application").strip()
                dept = str(app.get("department") or app.get("business_unit") or "Enterprise Estate").strip()
                eonid = str(app.get("eonid") or app.get("asset_id") or "").strip()
                tai = str(app.get("tai_system") or app_name).strip()
                builds = app.get("builds") if isinstance(app.get("builds"), list) else [{}]
                deployments = app.get("deployments") if isinstance(app.get("deployments"), list) else [{}]
                components = app.get("components") if isinstance(app.get("components"), list) else []

                primary_build = builds[0] if builds and isinstance(builds[0], dict) else {}
                primary_deploy = deployments[0] if deployments and isinstance(deployments[0], dict) else {}
                records.append(
                    {
                        "application_id": app_id,
                        "application_name": app_name,
                        "department": dept,
                        "eonid": eonid,
                        "tai_system": tai,
                        "build_id": str(primary_build.get("build_id") or app.get("build_id") or f"build:{app_name}:1"),
                        "build_version": str(primary_build.get("version") or app.get("version") or "1.0.0"),
                        "deployment_id": str(primary_deploy.get("deployment_id") or app.get("deployment_id") or f"deploy:{app_name}:prod"),
                        "environment": str(primary_deploy.get("environment") or app.get("environment") or "production"),
                        "region": str(primary_deploy.get("region") or app.get("region") or "global"),
                        "observed_at": str(app.get("observed_at") or payload.get("observed_at") or now_iso()),
                        "graph_available": bool(app.get("graph_available") or app.get("has_dependency_graph", False)),
                        "all_builds": [b for b in builds if isinstance(b, dict)],
                        "all_deployments": [d for d in deployments if isinstance(d, dict)],
                        "components": [c for c in components if isinstance(c, dict)],
                    }
                )
        elif isinstance(payload.get("records"), list):
            for row in payload["records"]:
                if isinstance(row, dict):
                    records.append(row)
    elif isinstance(payload, list):
        for row in payload:
            if isinstance(row, dict):
                records.append(row)

    # Group flat tabular/CSV-style rows by (application_id, build_id, deployment_id) if needed
    grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    normalized_docs: List[Dict[str, Any]] = []

    for rec in records:
        if "components" in rec and isinstance(rec["components"], list):
            grouped_key = (
                str(rec.get("application_id") or rec.get("application_name") or "app"),
                str(rec.get("build_id") or "build-1"),
                str(rec.get("deployment_id") or "deploy-1"),
            )
            grouped[grouped_key] = rec
        else:
            app_id = str(rec.get("application_id") or rec.get("app_id") or rec.get("application") or "app").strip()
            build_id = str(rec.get("build_id") or rec.get("build") or f"build:{app_id}:1").strip()
            deploy_id = str(rec.get("deployment_id") or rec.get("deployment") or f"deploy:{app_id}:prod").strip()
            g = grouped.setdefault(
                (app_id, build_id, deploy_id),
                {
                    "application_id": app_id,
                    "application_name": str(rec.get("application_name") or rec.get("application") or app_id),
                    "department": str(rec.get("department") or rec.get("business_unit") or "Enterprise Estate"),
                    "eonid": str(rec.get("eonid") or ""),
                    "tai_system": str(rec.get("tai_system") or app_id),
                    "build_id": build_id,
                    "build_version": str(rec.get("build_version") or rec.get("app_version") or "1.0.0"),
                    "deployment_id": deploy_id,
                    "environment": str(rec.get("environment") or "production"),
                    "region": str(rec.get("region") or "global"),
                    "observed_at": str(rec.get("observed_at") or now_iso()),
                    "graph_available": bool(rec.get("graph_available", False)),
                    "components": [],
                },
            )
            g["components"].append(rec)

    for g in grouped.values():
        app_identity = _derive_application_identity(
            explicit_app_id=str(g.get("application_id") or ""),
            comp_group=str(g.get("department") or ""),
            comp_name=str(g.get("application_name") or ""),
            fallback_stem=Path(source_path).stem,
            department=str(g.get("department") or "Enterprise Estate"),
            eonid=str(g.get("eonid") or ""),
            tai_system=str(g.get("tai_system") or ""),
        )
        observed_at = normalize_iso_timestamp(g.get("observed_at"), fallback=now_iso())
        build_id = str(g.get("build_id") or f"build:{app_identity['proj']}:1").strip()
        deploy_id = str(g.get("deployment_id") or f"deploy:{app_identity['proj']}:prod").strip()
        environment = str(g.get("environment") or "production").strip().lower()
        region = str(g.get("region") or "global").strip()
        comps = g.get("components") or []

        mapped_observations: List[Dict[str, Any]] = []
        unmapped_records: List[Dict[str, Any]] = []
        any_explicit_graph = bool(g.get("graph_available", False))

        for idx, comp in enumerate(comps):
            raw_purl = str(comp.get("purl") or "").strip()
            raw_name = str(comp.get("name") or comp.get("artifact") or comp.get("package") or "").strip()
            raw_group = str(comp.get("group") or comp.get("namespace_meta") or "").strip()
            raw_ver = str(comp.get("version") or comp.get("release") or "").strip()
            raw_eco = str(comp.get("ecosystem") or comp.get("namespace") or "maven").strip().lower()

            if raw_purl:
                parsed = parse_purl_rich(raw_purl, comp)
            elif raw_name:
                coord = f"{raw_group}/{raw_name}" if raw_group else raw_name
                parsed = parse_purl_rich(f"pkg:{raw_eco}/{coord}@{raw_ver or 'unspecified'}", comp)
            else:
                parsed = {"valid": False, "error": "Inventory component missing both purl and package name"}

            if not parsed.get("valid") or not parsed.get("namespace") or not parsed.get("proj"):
                unmapped_records.append(
                    {
                        "source_path": str(source_path),
                        "source_format": "company_inventory",
                        "application_id": app_identity["application_id"],
                        "build_id": build_id,
                        "raw_identifier": raw_purl or str(comp.get("id") or f"row-{idx}"),
                        "name": raw_name,
                        "version": raw_ver,
                        "reason": str(parsed.get("error") or "Invalid or unmapped inventory coordinates"),
                    }
                )
                continue

            if parsed["release"].startswith("${") or parsed["release"] == "unspecified":
                unmapped_records.append(
                    {
                        "source_path": str(source_path),
                        "source_format": "company_inventory",
                        "application_id": app_identity["application_id"],
                        "build_id": build_id,
                        "raw_identifier": raw_purl or raw_name,
                        "name": raw_name or parsed["proj"],
                        "version": raw_ver or parsed["release"],
                        "reason": f"Unspecified or unpinned version in inventory feed: {raw_ver or parsed['release']}",
                    }
                )
                continue

            canon_rel = canonical_release(parsed["namespace"], parsed["release"])
            library_id = make_library_id(parsed["namespace"], parsed["meta"], parsed["proj"], canon_rel)

            raw_rel_class = str(
                comp.get("dependency_classification")
                or comp.get("dependency_type")
                or comp.get("relationship")
                or ""
            ).strip().lower()
            if "direct" in comp and comp.get("direct") is not None and not raw_rel_class:
                d_val = str(comp.get("direct")).strip().lower()
                if d_val in {"1", "true", "direct"}:
                    raw_rel_class = "direct"
                elif d_val in {"0", "false", "transitive"}:
                    raw_rel_class = "transitive"
                else:
                    raw_rel_class = "unknown"

            dep_path_raw = comp.get("dependency_path") or comp.get("dependency_paths") or []
            dep_paths: List[List[str]] = []
            if isinstance(dep_path_raw, str) and dep_path_raw.strip():
                dep_paths = [[seg.strip() for seg in dep_path_raw.split("->") if seg.strip()]]
            elif isinstance(dep_path_raw, list) and dep_path_raw:
                if all(isinstance(x, str) for x in dep_path_raw):
                    dep_paths = [[str(x) for x in dep_path_raw]]
                else:
                    dep_paths = [[str(x) for x in p] for p in dep_path_raw if isinstance(p, list)]

            if raw_rel_class in {"direct", "transitive"}:
                dep_classification = raw_rel_class
                any_explicit_graph = True
            elif dep_paths:
                dep_classification = "direct" if len(dep_paths[0]) <= 2 else "transitive"
                any_explicit_graph = True
            else:
                dep_classification = "unknown"

            parent_id = ""
            raw_parent = str(comp.get("parent_id") or comp.get("parent_purl") or "").strip()
            if dep_classification == "transitive":
                if raw_parent.startswith("pkg:"):
                    p_parsed = parse_purl_rich(raw_parent)
                    if p_parsed.get("valid"):
                        parent_id = make_library_id(
                            p_parsed["namespace"],
                            p_parsed["meta"],
                            p_parsed["proj"],
                            canonical_release(p_parsed["namespace"], p_parsed["release"]),
                        )
                elif "|" in raw_parent:
                    parent_id = raw_parent
                elif dep_paths and len(dep_paths[0]) >= 3:
                    parent_step = dep_paths[0][-2]
                    if parent_step.startswith("pkg:"):
                        p_parsed = parse_purl_rich(parent_step)
                        if p_parsed.get("valid"):
                            parent_id = make_library_id(
                                p_parsed["namespace"],
                                p_parsed["meta"],
                                p_parsed["proj"],
                                canonical_release(p_parsed["namespace"], p_parsed["release"]),
                            )

            raw_scope = str(comp.get("scope") or comp.get("qualifier") or "runtime").strip().lower()
            qualifier = classify_scope_qualifier(raw_scope)
            supplier = str(comp.get("supplier") or comp.get("vendor") or "").strip()
            comp_observed = normalize_iso_timestamp(comp.get("observed_at"), fallback=observed_at)

            identity_status, is_repackaged, uncertain_reasons = detect_identity_status(
                explicit_purl=raw_purl,
                parsed_purl=parsed,
                raw_version=raw_ver or parsed["raw_release"],
                supplier_or_origin=supplier,
            )
            if dep_classification == "unknown":
                uncertain_reasons = list(uncertain_reasons) + [
                    "Inventory record has no dependency graph classification; classified as 'unknown'."
                ]

            digests = normalize_digests(comp.get("digests") or comp.get("hashes") or comp.get("artifact_digest"))

            mapped_observations.append(
                {
                    "library_id": library_id,
                    "purl": parsed["full_purl"],
                    "raw_purl": parsed.get("raw_purl") or parsed["full_purl"],
                    "base_purl": parsed["base_purl"],
                    "namespace": parsed["namespace"],
                    "meta": parsed["meta"],
                    "proj": parsed["proj"],
                    "release": canon_rel,
                    "qualifiers": parsed["qualifiers"],
                    "subpath": parsed["subpath"],
                    "digests": digests,
                    "scope": raw_scope,
                    "qualifier": qualifier,
                    "dependency_classification": dep_classification,
                    "direct": 1 if dep_classification == "direct" else (0 if dep_classification == "transitive" else None),
                    "parent_id": parent_id,
                    "dependency_paths": dep_paths,
                    "observed_at": comp_observed,
                    "build_id": str(comp.get("build_id") or build_id),
                    "deployment_id": str(comp.get("deployment_id") or deploy_id),
                    "environment": str(comp.get("environment") or environment).lower(),
                    "supplier": supplier,
                    "identity_status": identity_status,
                    "is_repackaged": is_repackaged,
                    "uncertain_match_reasons": uncertain_reasons,
                }
            )

        extra_builds = [
            {
                "build_id": str(b.get("build_id") or build_id),
                "version": str(b.get("version") or g.get("build_version") or "1.0.0"),
                "commit_sha": str(b.get("commit_sha") or ""),
                "bom_serial_number": str(b.get("bom_serial_number") or ""),
                "source_format": "company_inventory",
                "source_path": str(source_path),
                "graph_available": any_explicit_graph,
                "observed_at": normalize_iso_timestamp(b.get("observed_at"), fallback=observed_at),
            }
            for b in (g.get("all_builds") or [{"build_id": build_id, "version": g.get("build_version", "1.0.0")}])
        ]
        extra_deployments = [
            {
                "deployment_id": str(d.get("deployment_id") or deploy_id),
                "environment": str(d.get("environment") or environment).lower(),
                "region": str(d.get("region") or region),
                "build_id": str(d.get("build_id") or build_id),
                "deployed_at": normalize_iso_timestamp(d.get("deployed_at"), fallback=observed_at),
            }
            for d in (g.get("all_deployments") or [{"deployment_id": deploy_id, "environment": environment, "region": region, "build_id": build_id}])
        ]

        normalized_docs.append(
            {
                "source_format": "company_inventory",
                "source_path": str(source_path),
                "application": app_identity,
                "build": extra_builds[0],
                "extra_builds": extra_builds[1:],
                "deployment": extra_deployments[0],
                "extra_deployments": extra_deployments[1:],
                "graph_available": any_explicit_graph,
                "components_total_observed": len(comps),
                "observations": mapped_observations,
                "unmapped_records": unmapped_records,
            }
        )

    return normalized_docs


def detect_and_parse_estate_source(path: Path) -> List[Dict[str, Any]]:
    """Auto-detect CycloneDX JSON, SPDX JSON, or company inventory JSON/CSV and parse."""

    if path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        return parse_company_inventory_feed(rows, source_path=str(path))

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        if str(payload.get("bomFormat") or "").lower() == "cyclonedx" or "components" in payload and "metadata" in payload:
            return [parse_cyclonedx_document(payload, source_path=str(path))]
        if "spdxVersion" in payload or ("packages" in payload and "creationInfo" in payload):
            return [parse_spdx_document(payload, source_path=str(path))]
    return parse_company_inventory_feed(payload, source_path=str(path))


def merge_estate_observations(
    parsed_documents: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge build and deployment observations into a deduplicated Estate Contract (`osera-estate-contract/v1`).

    Key invariant:
    - Applications are deduplicated by `application_id` so repeated SBOM imports across
      multiple builds or deployment environments NEVER inflate application or exposure counts.
    - Every build (`builds[]`) and deployment (`deployments[]`) remains individually traceable.
    - Component observations within an application are keyed by exact `purl` (preserving qualifiers
      and subpaths) and also summarized by `library_id` for backward-compatible scope dataset joins.
    """

    apps_by_id: Dict[str, Dict[str, Any]] = {}
    all_unmapped: List[Dict[str, Any]] = []
    sources_by_format: Dict[str, int] = {"cyclonedx": 0, "spdx": 0, "company_inventory": 0}
    total_raw_components = 0
    total_mapped_components = 0
    builds_with_graph = 0
    builds_missing_graph = 0

    for doc in parsed_documents:
        fmt = str(doc.get("source_format") or "cyclonedx")
        sources_by_format[fmt] = sources_by_format.get(fmt, 0) + 1
        total_raw_components += int(doc.get("components_total_observed") or 0)
        observations = doc.get("observations") or []
        total_mapped_components += len(observations)
        all_unmapped.extend(doc.get("unmapped_records") or [])

        if doc.get("graph_available"):
            builds_with_graph += 1
        else:
            builds_missing_graph += 1

        app_info = doc["application"]
        app_id = app_info["application_id"]
        if app_id not in apps_by_id:
            apps_by_id[app_id] = {
                "application_id": app_id,
                "name": app_info["name"],
                "namespace": app_info["namespace"],
                "meta": app_info["meta"],
                "proj": app_info["proj"],
                "project_ref": app_info["project_ref"],
                "department": app_info["department"],
                "eonid": app_info.get("eonid") or f"SBOM-{len(apps_by_id) + 1}",
                "tai_system": app_info.get("tai_system") or app_info["name"],
                "builds_by_id": {},
                "deployments_by_id": {},
                "components_by_purl": {},
            }

        app_entry = apps_by_id[app_id]
        if app_info.get("department") and app_entry["department"] == "SBOM Scan":
            app_entry["department"] = app_info["department"]
        if app_info.get("eonid") and app_entry["eonid"].startswith("SBOM-"):
            app_entry["eonid"] = app_info["eonid"]

        for b in [doc["build"]] + list(doc.get("extra_builds") or []):
            bid = b["build_id"]
            app_entry["builds_by_id"][bid] = b

        for d in [doc["deployment"]] + list(doc.get("extra_deployments") or []):
            did = d["deployment_id"]
            app_entry["deployments_by_id"][did] = d

        for obs in observations:
            purl_key = obs["purl"]
            existing = app_entry["components_by_purl"].get(purl_key)
            raw_purl_val = str(obs.get("raw_purl") or obs["purl"])
            if not existing:
                obs_purls = [obs["purl"]]
                if raw_purl_val not in obs_purls:
                    obs_purls.append(raw_purl_val)
                app_entry["components_by_purl"][purl_key] = {
                    "library_id": obs["library_id"],
                    "purl": obs["purl"],
                    "raw_purl": raw_purl_val,
                    "observed_purls": obs_purls,
                    "base_purl": obs["base_purl"],
                    "namespace": obs["namespace"],
                    "meta": obs["meta"],
                    "proj": obs["proj"],
                    "release": obs["release"],
                    "qualifiers": dict(obs.get("qualifiers") or {}),
                    "subpath": obs.get("subpath") or "",
                    "digests": list(obs.get("digests") or []),
                    "scopes": [obs["scope"]] if obs.get("scope") else [],
                    "qualifier": obs.get("qualifier") or "runtime",
                    "dependency_classification": obs["dependency_classification"],
                    "parent_ids": [obs["parent_id"]] if obs.get("parent_id") else [],
                    "dependency_paths": list(obs.get("dependency_paths") or []),
                    "first_observed_at": obs["observed_at"],
                    "observed_at": obs["observed_at"],
                    "build_ids": [obs["build_id"]] if obs.get("build_id") else [],
                    "deployment_ids": [obs["deployment_id"]] if obs.get("deployment_id") else [],
                    "environments": [obs["environment"]] if obs.get("environment") else [],
                    "supplier": obs.get("supplier") or "",
                    "identity_status": obs.get("identity_status") or "exact",
                    "is_repackaged": bool(obs.get("is_repackaged", False)),
                    "uncertain_match_reasons": list(obs.get("uncertain_match_reasons") or []),
                }
            else:
                # Merge without inflating application exposure count:
                # Upgrade dependency_classification if a richer build provides a graph (`direct` > `transitive` > `unknown`)
                prev_cls = existing["dependency_classification"]
                new_cls = obs["dependency_classification"]
                if prev_cls == "unknown" and new_cls in {"direct", "transitive"}:
                    existing["dependency_classification"] = new_cls
                    existing["uncertain_match_reasons"] = [
                        r for r in existing["uncertain_match_reasons"] if "classified as 'unknown'" not in r
                    ]
                elif prev_cls == "transitive" and new_cls == "direct":
                    existing["dependency_classification"] = "direct"

                if obs.get("qualifier") == "runtime":
                    existing["qualifier"] = "runtime"

                for d_hash in obs.get("digests") or []:
                    if d_hash not in existing["digests"]:
                        existing["digests"].append(d_hash)
                for sc in ([obs["scope"]] if obs.get("scope") else []):
                    if sc not in existing["scopes"]:
                        existing["scopes"].append(sc)
                if obs.get("parent_id") and obs["parent_id"] not in existing["parent_ids"]:
                    existing["parent_ids"].append(obs["parent_id"])
                for path in obs.get("dependency_paths") or []:
                    if path not in existing["dependency_paths"] and len(existing["dependency_paths"]) < 8:
                        existing["dependency_paths"].append(path)
                if obs.get("build_id") and obs["build_id"] not in existing["build_ids"]:
                    existing["build_ids"].append(obs["build_id"])
                if obs.get("deployment_id") and obs["deployment_id"] not in existing["deployment_ids"]:
                    existing["deployment_ids"].append(obs["deployment_id"])
                if obs.get("environment") and obs["environment"] not in existing["environments"]:
                    existing["environments"].append(obs["environment"])
                if obs["observed_at"] < existing["first_observed_at"]:
                    existing["first_observed_at"] = obs["observed_at"]
                if obs["observed_at"] > existing["observed_at"]:
                    existing["observed_at"] = obs["observed_at"]
                if obs.get("is_repackaged"):
                    existing["is_repackaged"] = True
                if obs.get("identity_status") == "ambiguous":
                    existing["identity_status"] = "ambiguous"
                elif obs.get("identity_status") == "qualified_or_repackaged" and existing["identity_status"] == "exact":
                    existing["identity_status"] = "qualified_or_repackaged"
                for reason in obs.get("uncertain_match_reasons") or []:
                    if reason not in existing["uncertain_match_reasons"]:
                        existing["uncertain_match_reasons"].append(reason)

    applications: List[Dict[str, Any]] = []
    all_builds_list: List[Dict[str, Any]] = []
    all_deployments_list: List[Dict[str, Any]] = []
    agg_components_by_id: Dict[str, Dict[str, Any]] = {}
    distinct_builds_total = 0
    distinct_deployments_total = 0
    unknown_dep_observations = 0
    ambiguous_identities_count = 0
    repackaged_libraries_count = 0
    apps_with_graph = 0
    apps_without_graph = 0

    for app_id in sorted(apps_by_id.keys()):
        raw_app = apps_by_id[app_id]
        builds = sorted(raw_app["builds_by_id"].values(), key=lambda x: (x.get("observed_at", ""), x["build_id"]))
        deployments = sorted(raw_app["deployments_by_id"].values(), key=lambda x: (x.get("environment", ""), x["deployment_id"]))
        components = sorted(raw_app["components_by_purl"].values(), key=lambda x: x["purl"])

        all_builds_list.extend(builds)
        all_deployments_list.extend(deployments)
        distinct_builds_total += len(builds)
        distinct_deployments_total += len(deployments)

        app_has_graph = any(c["dependency_classification"] in {"direct", "transitive"} for c in components)
        if app_has_graph:
            apps_with_graph += 1
        else:
            apps_without_graph += 1

        for comp in components:
            if comp["dependency_classification"] == "unknown":
                unknown_dep_observations += 1
            if comp["identity_status"] != "exact":
                ambiguous_identities_count += 1
            if comp["is_repackaged"]:
                repackaged_libraries_count += 1

            lid = comp["library_id"]
            comp_purls = list(comp.get("observed_purls") or [comp["purl"]])
            agg = agg_components_by_id.get(lid)
            if not agg:
                agg = {
                    "library_id": lid,
                    "namespace": comp["namespace"],
                    "meta": comp["meta"],
                    "proj": comp["proj"],
                    "release": comp["release"],
                    "observed_purls": list(comp_purls),
                    "qualifiers": {k: [v] for k, v in (comp.get("qualifiers") or {}).items()},
                    "subpaths": [comp["subpath"]] if comp.get("subpath") else [],
                    "digests": list(comp.get("digests") or []),
                    "dependency_paths": list(comp.get("dependency_paths") or []),
                    "scopes": list(comp.get("scopes") or []),
                    "observed_at": comp.get("observed_at") or "",
                    "identity_status": comp.get("identity_status") or "exact",
                    "is_repackaged": bool(comp.get("is_repackaged", False)),
                    "uncertain_match_reasons": list(comp.get("uncertain_match_reasons") or []),
                    "consumer_app_ids": [app_id],
                    "direct_app_ids": [app_id] if comp["dependency_classification"] == "direct" else [],
                    "transitive_app_ids": [app_id] if comp["dependency_classification"] == "transitive" else [],
                    "unknown_app_ids": [app_id] if comp["dependency_classification"] == "unknown" else [],
                }
                agg_components_by_id[lid] = agg
            else:
                for p_str in comp_purls:
                    if p_str not in agg["observed_purls"]:
                        agg["observed_purls"].append(p_str)
                for qk, qv in (comp.get("qualifiers") or {}).items():
                    qlist = agg["qualifiers"].setdefault(qk, [])
                    if qv not in qlist:
                        qlist.append(qv)
                if comp.get("subpath") and comp["subpath"] not in agg["subpaths"]:
                    agg["subpaths"].append(comp["subpath"])
                for dg in comp.get("digests") or []:
                    if dg not in agg["digests"]:
                        agg["digests"].append(dg)
                for dp in comp.get("dependency_paths") or []:
                    if dp not in agg["dependency_paths"]:
                        agg["dependency_paths"].append(dp)
                for sc in comp.get("scopes") or []:
                    if sc not in agg["scopes"]:
                        agg["scopes"].append(sc)
                if (comp.get("observed_at") or "") > (agg.get("observed_at") or ""):
                    agg["observed_at"] = comp["observed_at"]
                if comp.get("is_repackaged"):
                    agg["is_repackaged"] = True
                if comp.get("identity_status") == "ambiguous":
                    agg["identity_status"] = "ambiguous"
                elif comp.get("identity_status") == "qualified_or_repackaged" and agg["identity_status"] == "exact":
                    agg["identity_status"] = "qualified_or_repackaged"
                for reason in comp.get("uncertain_match_reasons") or []:
                    if reason not in agg["uncertain_match_reasons"]:
                        agg["uncertain_match_reasons"].append(reason)
                if app_id not in agg["consumer_app_ids"]:
                    agg["consumer_app_ids"].append(app_id)
                if comp["dependency_classification"] == "direct" and app_id not in agg["direct_app_ids"]:
                    agg["direct_app_ids"].append(app_id)
                elif comp["dependency_classification"] == "transitive" and app_id not in agg["transitive_app_ids"]:
                    agg["transitive_app_ids"].append(app_id)
                elif comp["dependency_classification"] == "unknown" and app_id not in agg["unknown_app_ids"]:
                    agg["unknown_app_ids"].append(app_id)

        latest_version = builds[-1]["version"] if builds else "0.0.0"
        applications.append(
            {
                "id": app_id,
                "application_id": app_id,
                "name": raw_app["name"],
                "namespace": raw_app["namespace"],
                "meta": raw_app["meta"],
                "proj": raw_app["proj"],
                "release": latest_version,
                "project_ref": raw_app["project_ref"],
                "department": raw_app["department"],
                "eonid": raw_app["eonid"],
                "tai_system": raw_app["tai_system"],
                "build_count": len(builds),
                "deployment_count": len(deployments),
                "environments": sorted({d["environment"] for d in deployments if d.get("environment")}),
                "builds": [b["build_id"] for b in builds],
                "build_records": builds,
                "deployments": [d["deployment_id"] for d in deployments],
                "deployment_records": deployments,
                "components": components,
            }
        )

    agg_components: List[Dict[str, Any]] = []
    for lid in sorted(agg_components_by_id.keys()):
        item = agg_components_by_id[lid]
        d_cnt = len(item["direct_app_ids"])
        t_cnt = len([a for a in item["transitive_app_ids"] if a not in item["direct_app_ids"]])
        u_cnt = len([a for a in item["unknown_app_ids"] if a not in item["direct_app_ids"] and a not in item["transitive_app_ids"]])
        if d_cnt > 0 and t_cnt == 0 and u_cnt == 0:
            dep_cls = "direct"
        elif t_cnt > 0 and d_cnt == 0 and u_cnt == 0:
            dep_cls = "transitive"
        elif u_cnt > 0 and d_cnt == 0 and t_cnt == 0:
            dep_cls = "unknown"
        else:
            dep_cls = "mixed"
        item["total_consumer_count"] = len(item["consumer_app_ids"])
        item["direct_consumer_count"] = d_cnt
        item["transitive_consumer_count"] = t_cnt
        item["unknown_consumer_count"] = u_cnt
        item["dependency_classification"] = dep_cls
        agg_components.append(item)

    completeness_ratio = (
        round(total_mapped_components / (total_mapped_components + len(all_unmapped)), 4)
        if (total_mapped_components + len(all_unmapped)) > 0
        else 1.0
    )

    completeness_obj = {
        "sources_processed": len(parsed_documents),
        "sources_by_format": {k: v for k, v in sources_by_format.items() if v > 0},
        "raw_sbom_documents_imported": len(parsed_documents),
        "deduplicated_applications": len(applications),
        "applications_with_dependency_graph": apps_with_graph,
        "applications_without_dependency_graph": apps_without_graph,
        "distinct_builds": distinct_builds_total,
        "distinct_deployments": distinct_deployments_total,
        "duplicate_imports_collapsed": max(0, len(parsed_documents) - len(applications)),
        "components_total_observed": total_raw_components,
        "components_mapped": total_mapped_components,
        "components_unmapped": len(all_unmapped),
        "unmapped_records": len(all_unmapped),
        "completeness_ratio": completeness_ratio,
        "graph_coverage": {
            "builds_with_graph": builds_with_graph,
            "builds_missing_graph": builds_missing_graph,
            "unknown_dependency_observations": unknown_dep_observations,
        },
        "ambiguous_identities_count": ambiguous_identities_count,
        "repackaged_libraries_count": repackaged_libraries_count,
        "unmapped_record_details": all_unmapped,
    }

    return {
        "schema_version": ESTATE_CONTRACT_SCHEMA_VERSION,
        "compatibility": {
            "scope_dataset_schema": SCOPE_DATASET_SCHEMA_VERSION,
            "backward_compatible": True,
        },
        "imported_at": now_iso(),
        "applications": applications,
        "builds": all_builds_list,
        "deployments": all_deployments_list,
        "components": agg_components,
        "completeness": completeness_obj,
        "completeness_report": completeness_obj,
        "unmapped_records": all_unmapped,
    }


def import_estate_sources(paths: Sequence[Path], scope: Optional[str] = None) -> Dict[str, Any]:
    """Import one or more files or directories of CycloneDX, SPDX, or inventory feeds."""

    files: List[Path] = []
    for p in paths:
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and child.suffix.lower() in {".json", ".csv"}:
                    files.append(child)
        elif p.is_file():
            files.append(p)

    parsed_docs: List[Dict[str, Any]] = []
    for file_path in files:
        parsed_docs.extend(detect_and_parse_estate_source(file_path))

    contract = merge_estate_observations(parsed_docs)
    if scope:
        contract["scope"] = scope
    return contract


def generate_remediation_recipes(
    estate_or_dataset: Any,
    scope_name: str = "scope",
) -> Dict[str, Any]:
    """Generate direct-dependency remediation recipes while blocking `unknown` (graphless) dependencies.

    Satisfies the acceptance criterion:
    'Missing graphs produce unknown dependency classification, not direct-dependency remediation recipes.'
    """

    recipes: List[Dict[str, Any]] = []
    skipped_unknown: List[Dict[str, Any]] = []
    skipped_transitive: List[Dict[str, Any]] = []
    suppressed_all: List[Dict[str, Any]] = []

    libraries_list: Optional[List[Dict[str, Any]]] = None
    if isinstance(estate_or_dataset, list):
        libraries_list = estate_or_dataset
    elif isinstance(estate_or_dataset, dict) and isinstance(estate_or_dataset.get("libraries"), list):
        libraries_list = estate_or_dataset["libraries"]

    if libraries_list is not None:
        for lib in libraries_list:
            lid = str(lib.get("id") or "")
            ns = str(lib.get("namespace") or "")
            meta = str(lib.get("meta") or "")
            proj = str(lib.get("proj") or "")
            rel = str(lib.get("release") or "")
            safe = str(lib.get("nearest_safe_version") or lib.get("max_safe_patch_same_minor") or "")
            direct_count = int(lib.get("direct_consumer_count") or 0)
            transitive_count = int(lib.get("transitive_consumer_count") or 0)
            unknown_count = int(lib.get("unknown_consumer_count") or 0)
            dep_class = str(lib.get("dependency_classification") or "")

            if direct_count == 0 and (unknown_count > 0 or dep_class == "unknown"):
                entry = {
                    "library_id": lid,
                    "coordinate": f"{meta}:{proj}" if meta else proj,
                    "current_release": rel,
                    "dependency_classification": "unknown",
                    "unknown_consumer_count": unknown_count or int(lib.get("total_consumer_count") or 0),
                    "reason": "dependency_classification_unknown_missing_graph",
                    "detail": "Missing dependency graph: classified as 'unknown' rather than direct; direct-dependency remediation recipe suppressed.",
                }
                skipped_unknown.append(entry)
                suppressed_all.append(entry)
                continue

            if direct_count == 0 and transitive_count > 0:
                entry = {
                    "library_id": lid,
                    "coordinate": f"{meta}:{proj}" if meta else proj,
                    "current_release": rel,
                    "dependency_classification": "transitive",
                    "reason": "no_direct_consumers_transitive_only",
                    "detail": "Transitive-only exposure; remediate via parent amplifier or BOM constraint rather than direct dependency recipe.",
                }
                skipped_transitive.append(entry)
                suppressed_all.append(entry)
                continue

            if direct_count > 0 and ns == "maven":
                recipes.append(
                    {
                        "library_id": lid,
                        "scope": scope_name,
                        "recipe_type": "org.openrewrite.java.dependencies.UpgradeDependencyVersion",
                        "groupId": meta,
                        "artifactId": proj,
                        "currentVersion": rel,
                        "newVersion": safe or rel,
                        "direct_consumer_count": direct_count,
                        "dependency_classification": "direct",
                    }
                )

    elif isinstance(estate_or_dataset, dict) and isinstance(estate_or_dataset.get("applications"), list):
        for app in estate_or_dataset["applications"]:
            app_id = app.get("application_id", "")
            for comp in app.get("components") or []:
                dep_class = comp.get("dependency_classification", "unknown")
                if dep_class == "unknown":
                    entry = {
                        "application_id": app_id,
                        "library_id": comp.get("library_id", ""),
                        "purl": comp.get("purl", ""),
                        "dependency_classification": "unknown",
                        "reason": "dependency_classification_unknown_missing_graph",
                        "detail": "Missing dependency graph: classified as 'unknown' rather than direct; direct-dependency remediation recipe suppressed.",
                    }
                    skipped_unknown.append(entry)
                    suppressed_all.append(entry)
                elif dep_class == "transitive":
                    entry = {
                        "application_id": app_id,
                        "library_id": comp.get("library_id", ""),
                        "purl": comp.get("purl", ""),
                        "dependency_classification": "transitive",
                        "reason": "no_direct_consumers_transitive_only",
                        "detail": "Transitive dependency; remediate via parent dependency path.",
                    }
                    skipped_transitive.append(entry)
                    suppressed_all.append(entry)
                elif dep_class == "direct" and comp.get("namespace") == "maven":
                    recipes.append(
                        {
                            "application_id": app_id,
                            "library_id": comp.get("library_id", ""),
                            "purl": comp.get("purl", ""),
                            "recipe_type": "org.openrewrite.java.dependencies.UpgradeDependencyVersion",
                            "groupId": comp.get("meta", ""),
                            "artifactId": comp.get("proj", ""),
                            "currentVersion": comp.get("release", ""),
                            "dependency_classification": "direct",
                        }
                    )

    return {
        "recipes": recipes,
        "direct_remediation_recipes": recipes,
        "suppressed": suppressed_all,
        "suppressed_unknown_dependencies": skipped_unknown,
        "suppressed_transitive_dependencies": skipped_transitive,
    }


def _match_overlay_rule(
    proj: Dict[str, Any],
    overlay: Dict[str, Any],
) -> Dict[str, Any]:
    """Match an application/project against private overlay rules without mutating shared core structures."""

    app_rules = overlay.get("applications") if isinstance(overlay.get("applications"), dict) else {}
    bu_rules = overlay.get("business_units") if isinstance(overlay.get("business_units"), dict) else {}
    defaults = overlay.get("defaults") if isinstance(overlay.get("defaults"), dict) else {}

    pid = str(proj.get("id") or proj.get("application_id") or "").strip()
    pref = str(proj.get("project_ref") or "").strip()
    pname = str(proj.get("proj") or proj.get("name") or "").strip()
    eonid = str(proj.get("eonid") or "").strip()
    dept = str(proj.get("department") or "").strip()

    matched_app: Dict[str, Any] = {}
    for candidate_key in (pid, pref, pname, eonid):
        if candidate_key and candidate_key in app_rules and isinstance(app_rules[candidate_key], dict):
            matched_app = app_rules[candidate_key]
            break

    matched_bu: Dict[str, Any] = {}
    if dept and dept in bu_rules and isinstance(bu_rules[dept], dict):
        matched_bu = bu_rules[dept]

    merged: Dict[str, Any] = copy.deepcopy(defaults)
    for layer in (matched_bu, matched_app):
        for k, v in layer.items():
            if v is not None:
                merged[k] = copy.deepcopy(v)

    ownership = merged.get("ownership") if isinstance(merged.get("ownership"), dict) else {}
    criticality = str(merged.get("criticality") or "medium").strip().lower()
    environment = str(merged.get("environment") or "production").strip().lower()
    exposure = str(merged.get("exposure") or "internal").strip().lower()
    runtime_constraints = (
        merged.get("runtime_constraints") if isinstance(merged.get("runtime_constraints"), dict) else {}
    )
    change_windows = merged.get("change_windows")
    if isinstance(change_windows, list):
        cw_dict: Dict[str, Any] = {"windows": change_windows}
        if any(isinstance(w, dict) and w.get("freeze_until") for w in change_windows):
            cw_dict["state"] = "frozen"
        change_windows = cw_dict
    elif not isinstance(change_windows, dict):
        change_windows = {}

    w_crit = CRITICALITY_WEIGHTS.get(criticality, 1.0)
    w_exp = EXPOSURE_WEIGHTS.get(exposure, 1.0)
    w_env = ENVIRONMENT_WEIGHTS.get(environment, 1.0)
    multiplier = round(w_crit * w_exp * w_env, 4)

    return {
        "ownership": {
            "team": str(ownership.get("team") or merged.get("owner_team") or "Unassigned"),
            "contact": str(ownership.get("contact") or ownership.get("owner_email") or merged.get("owner_contact") or ""),
            "business_unit": str(ownership.get("business_unit") or ownership.get("department") or dept or "General"),
            "cost_center": str(ownership.get("cost_center") or ""),
        },
        "criticality": criticality,
        "environment": environment,
        "exposure": exposure,
        "runtime_constraints": runtime_constraints,
        "change_windows": change_windows,
        "priority_multiplier": multiplier,
    }


def apply_company_overlay(
    dataset: Dict[str, Any],
    overlay: Dict[str, Any],
    *,
    filters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply a private company overlay to filter and reprioritize a scope dataset in memory.

    Invariants:
    - Does not mutate the input `dataset` or require changes to shared core schema.
    - Re-computes priority scores (`overlay_priority_score`, `effective_risk_signal`)
      and recommended actions when runtime constraints or change windows apply.
    - Provides `export_public_view()` / `sanitize_for_public_export()` so private
      inventory and ownership metadata are never disclosed in external requests.
    """

    overlay_filters = overlay.get("filters") if isinstance(overlay.get("filters"), dict) else {}
    active_filters = {**overlay_filters, **(filters if isinstance(filters, dict) else {})}
    view = copy.deepcopy(dataset)

    projects = view.get("consumer_projects") or []
    context_by_project: Dict[str, Dict[str, Any]] = {}
    filtered_projects: List[Dict[str, Any]] = []

    for proj in projects:
        pid = str(proj.get("id") or "")
        ctx = _match_overlay_rule(proj, overlay)
        context_by_project[pid] = ctx

        crit_filter = active_filters.get("criticality") or active_filters.get("criticalities")
        if crit_filter:
            allowed = {str(x).lower() for x in (crit_filter if isinstance(crit_filter, list) else [crit_filter])}
            if ctx["criticality"] not in allowed:
                continue
        exp_filter = active_filters.get("exposure") or active_filters.get("exposures")
        if exp_filter:
            allowed = {str(x).lower() for x in (exp_filter if isinstance(exp_filter, list) else [exp_filter])}
            if ctx["exposure"] not in allowed:
                continue
        env_filter = active_filters.get("environment") or active_filters.get("environments")
        if env_filter:
            allowed = {str(x).lower() for x in (env_filter if isinstance(env_filter, list) else [env_filter])}
            if ctx["environment"] not in allowed:
                continue
        if active_filters.get("owner_team"):
            if ctx["ownership"]["team"].lower() != str(active_filters["owner_team"]).strip().lower():
                continue
        if active_filters.get("business_unit"):
            if ctx["ownership"]["business_unit"].lower() != str(active_filters["business_unit"]).strip().lower():
                continue
        if active_filters.get("exclude_frozen_change_windows"):
            cw_state = str(ctx["change_windows"].get("state") or ctx["change_windows"].get("status") or "").lower()
            if cw_state == "frozen":
                continue

        proj_enriched = dict(proj)
        proj_enriched["company_context"] = ctx
        if ctx["ownership"].get("business_unit"):
            proj_enriched["department"] = ctx["ownership"]["business_unit"]
        base_cvss = float(proj.get("max_cvss") or 0.0)
        kev_cnt = int(proj.get("kev_vulnerability_count") or 0)
        vuln_cnt = int(proj.get("vulnerable_library_count") or 0)
        proj_enriched["overlay_priority_score"] = round(
            (base_cvss * 5.0 + kev_cnt * 20.0 + vuln_cnt * 2.5) * ctx["priority_multiplier"],
            2,
        )
        filtered_projects.append(proj_enriched)

    filtered_projects.sort(
        key=lambda p: (-float(p.get("overlay_priority_score") or 0.0), -int(p.get("vulnerable_library_count") or 0), str(p.get("id") or ""))
    )
    allowed_project_ids = {str(p["id"]) for p in filtered_projects if p.get("id")}

    filtered_libraries: List[Dict[str, Any]] = []
    for lib in view.get("libraries") or []:
        consumers = [pid for pid in (lib.get("consumer_project_ids") or []) if pid in allowed_project_ids]
        if not consumers:
            continue
        direct_consumers = [pid for pid in (lib.get("direct_consumer_project_ids") or []) if pid in allowed_project_ids]
        unknown_consumers = [pid for pid in (lib.get("unknown_consumer_project_ids") or []) if pid in allowed_project_ids]

        lib_copy = dict(lib)
        lib_copy["consumer_project_ids"] = consumers
        lib_copy["direct_consumer_project_ids"] = direct_consumers
        if "unknown_consumer_project_ids" in lib_copy:
            lib_copy["unknown_consumer_project_ids"] = unknown_consumers
        lib_copy["total_consumer_count"] = len(consumers)
        lib_copy["direct_consumer_count"] = len(direct_consumers)
        lib_copy["unknown_consumer_count"] = len(unknown_consumers)
        lib_copy["transitive_consumer_count"] = max(0, len(consumers) - len(direct_consumers) - len(unknown_consumers))

        multipliers = [context_by_project[pid]["priority_multiplier"] for pid in consumers if pid in context_by_project]
        max_multiplier = max(multipliers) if multipliers else 1.0
        avg_multiplier = (sum(multipliers) / len(multipliers)) if multipliers else 1.0

        effort = str(lib.get("effort_class") or "UNKNOWN").upper()
        effort_rank = EFFORT_RANK.get(effort, 5)
        is_kev = bool(lib.get("is_kev_listed"))

        runtime_constrained = False
        constraint_reasons: List[str] = []
        change_window_blocked = False
        emergency_kev_override = False

        for pid in consumers:
            ctx = context_by_project.get(pid, {})
            rc = ctx.get("runtime_constraints") or {}
            max_up = str(rc.get("max_allowed_upgrade") or "").upper()
            if max_up in EFFORT_RANK and effort_rank > EFFORT_RANK[max_up]:
                runtime_constrained = True
                reason = f"{pid}: effort {effort} exceeds max_allowed_upgrade={max_up}"
                if reason not in constraint_reasons:
                    constraint_reasons.append(reason)
            if bool(rc.get("major_upgrade_blocked")) and effort in {"MAJOR", "DEAD_END"}:
                runtime_constrained = True
                reason = f"{pid}: major upgrade blocked by runtime constraint"
                if reason not in constraint_reasons:
                    constraint_reasons.append(reason)
            if bool(rc.get("pinned_runtime") or rc.get("backpatch_only")) and effort in {"MINOR", "MAJOR", "DEAD_END"}:
                runtime_constrained = True
                reason = f"{pid}: runtime is pinned / backpatch-only"
                if reason not in constraint_reasons:
                    constraint_reasons.append(reason)
            pinned_libs = rc.get("pinned_libraries") if isinstance(rc.get("pinned_libraries"), dict) else {}
            coord_key = f"{lib.get('meta')}:{lib.get('proj')}" if lib.get("meta") else str(lib.get("proj") or "")
            if coord_key in pinned_libs or str(lib.get("id")) in pinned_libs:
                runtime_constrained = True
                reason = f"{pid}: package {coord_key} is runtime-pinned ({pinned_libs.get(coord_key) or pinned_libs.get(str(lib.get('id')))})"
                if reason not in constraint_reasons:
                    constraint_reasons.append(reason)

            cw = ctx.get("change_windows") or {}
            cw_state = str(cw.get("state") or cw.get("status") or "open").lower()
            if cw_state in {"frozen", "blackout", "embargo"}:
                if is_kev and bool(cw.get("emergency_kev_override", True)):
                    emergency_kev_override = True
                else:
                    change_window_blocked = True

        if active_filters.get("runtime_constrained_only") and not runtime_constrained:
            continue

        base_signal = float(lib.get("risk_signal") or 0.0)
        constraint_boost = 1.25 if runtime_constrained else 1.0
        effective_signal = round(base_signal * ((max_multiplier * 0.65) + (avg_multiplier * 0.35)) * constraint_boost, 6)

        overlay_action = "STANDARD_REMEDIATION"
        if len(direct_consumers) == 0 and len(unknown_consumers) > 0:
            overlay_action = "CAPTURE_DEPENDENCY_GRAPH_FIRST"
        elif runtime_constrained:
            overlay_action = "CREATE_LIBRARY_FORK"
        elif change_window_blocked and not emergency_kev_override:
            overlay_action = "DEFER_TO_NEXT_CHANGE_WINDOW_OR_STAGE_BACKPATCH"
        elif emergency_kev_override:
            overlay_action = "EMERGENCY_KEV_CHANGE_WINDOW_OVERRIDE"

        lib_copy["base_risk_signal"] = base_signal
        lib_copy["risk_signal"] = effective_signal
        lib_copy["effective_risk_signal"] = effective_signal
        eval_obj = {
            "max_business_multiplier": max_multiplier,
            "avg_business_multiplier": round(avg_multiplier, 4),
            "runtime_constrained": runtime_constrained,
            "runtime_constraint_reasons": constraint_reasons,
            "change_window_blocked": change_window_blocked,
            "emergency_kev_override": emergency_kev_override,
            "overlay_recommended_action": overlay_action,
            "criticalities_affected": sorted({context_by_project[pid]["criticality"] for pid in consumers if pid in context_by_project}),
            "exposures_affected": sorted({context_by_project[pid]["exposure"] for pid in consumers if pid in context_by_project}),
            "environments_affected": sorted({context_by_project[pid]["environment"] for pid in consumers if pid in context_by_project}),
            "owner_teams": sorted({context_by_project[pid]["ownership"]["team"] for pid in consumers if pid in context_by_project}),
        }
        lib_copy["overlay_evaluation"] = eval_obj
        lib_copy["overlay_priority"] = eval_obj
        lib_copy["overlay_recommended_action"] = overlay_action
        filtered_libraries.append(lib_copy)

    filtered_libraries.sort(key=lambda l: (-float(l.get("effective_risk_signal") or 0.0), str(l.get("id") or "")))
    view["consumer_projects"] = filtered_projects
    view["libraries"] = filtered_libraries
    view.setdefault("meta", {})["company_overlay_applied"] = {
        "schema_version": str(overlay.get("schema_version") or COMPANY_OVERLAY_SCHEMA_VERSION),
        "private_local_only": True,
        "filtered_projects": len(filtered_projects),
        "filtered_libraries": len(filtered_libraries),
    }
    return view


def sanitize_for_public_export(dataset_or_requests: Dict[str, Any]) -> Dict[str, Any]:
    """Strip all private company overlay fields, owners, internal IDs, and deployment details before sharing."""

    cleaned = copy.deepcopy(dataset_or_requests)
    cleaned.pop("unmapped_records", None)
    cleaned.pop("company_overlay", None)
    if isinstance(cleaned.get("meta"), dict):
        cleaned["meta"].pop("company_overlay_applied", None)
        cleaned["meta"].pop("company_overlay", None)
        if isinstance(cleaned["meta"].get("estate_import"), dict):
            cleaned["meta"]["estate_import"].pop("completeness", None)
    for proj in cleaned.get("consumer_projects") or []:
        if isinstance(proj, dict):
            proj.pop("company_context", None)
            proj.pop("company_overlay", None)
            proj.pop("overlay_priority_score", None)
            proj.pop("builds", None)
            proj.pop("deployments", None)
            proj.pop("environments", None)
            proj["department"] = "General"
    for lib in cleaned.get("libraries") or []:
        if isinstance(lib, dict):
            if "base_risk_signal" in lib:
                lib["risk_signal"] = lib.pop("base_risk_signal")
            lib.pop("overlay_evaluation", None)
            lib.pop("overlay_priority", None)
            lib.pop("overlay_recommended_action", None)
            lib.pop("effective_risk_signal", None)
    return cleaned

#!/usr/bin/env python3
"""Standard Package URL (PURL) identity parsing, normalization, serialization, and legacy transition helpers (#71).

Follows the official Package URL specification (https://github.com/package-url/purl-spec):
  pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

Key invariants:
- Distinguishes:
  1. Versionless package identity (`pkg:<type>/<namespace>/<name>`)
  2. Versioned artifact identity (`pkg:<type>/<namespace>/<name>@<version>[?<qualifiers>][#<subpath>]`)
  3. Version range / applicability expressions (`^1.2.0`, `>=1.0,<2.0`, `1.2.x`, `${prop}`, `unspecified`),
     which are never turned into exact artifact identities.
- Preserves ecosystem normalization rules (PyPI `[-_.]+` -> `-` lowercase, npm `@scope` percent-encoded as
  `%40scope` and lowercased, Maven groupId/artifactId case preserved, Debian/Alpine lowercased).
- Preserves qualifiers and subpaths as part of exact artifact identity so distinct artifacts (e.g.
  `?classifier=sources` vs default jar) never silently collapse.
- Explicitly translates documented legacy 4-part (`namespace|meta|proj|release`) and 3-part
  (`namespace|meta|proj`) pipe-delimited library identifiers during transition, while keeping non-package
  identifiers (`github|<org>|<repo>` consumer project IDs, business scope IDs, CVE IDs) separate and
  rejecting ambiguous colon-separated coordinates (`org.springframework:spring-web:5.3.39`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import quote, unquote

PURL_TYPE_RE = re.compile(r"^[a-z][a-z0-9.+-]*$")
QUALIFIER_KEY_RE = re.compile(r"^[a-z][a-z0-9._-]*$")

KNOWN_PACKAGE_ECOSYSTEMS = frozenset(
    {
        "maven",
        "npm",
        "pypi",
        "rpm",
        "deb",
        "apk",
        "cargo",
        "golang",
        "nuget",
        "gem",
        "composer",
        "oci",
        "docker",
        "generic",
        "hex",
        "pub",
        "swift",
        "cocoapods",
        "cran",
        "hackage",
        "conan",
    }
)

NON_PACKAGE_NAMESPACES = frozenset({"github", "gitlab", "bitbucket", "scope", "project", "app", "system"})

LOWERCASE_NAME_TYPES = frozenset({"pypi", "npm", "deb", "apk", "composer", "github", "bitbucket", "hex", "pub"})
LOWERCASE_NAMESPACE_TYPES = frozenset({"npm", "deb", "apk", "rpm", "composer", "github", "bitbucket"})

ECOSYSTEM_LABELS: Dict[str, str] = {
    "maven": "Java",
    "npm": "JavaScript",
    "pypi": "Python",
    "nuget": ".NET",
    "cargo": "Rust",
    "golang": "Go",
    "gem": "Ruby",
    "composer": "PHP",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "docker": "Docker",
    "oci": "OCI",
    "generic": "Generic",
}

_RANGE_OR_UNRESOLVED_RE = re.compile(
    r"(?:^\s*$|^unspecified$|^latest$|^unknown$|^\*$|[\^~><=|()\[\]{}$]|\s+|\.(?:x|X|\*)$)"
)


def is_version_range_or_unresolved(version: Any) -> bool:
    """Return True when version is empty, unresolved placeholder, or a version range expression."""
    if not isinstance(version, str):
        return True
    raw = version.strip()
    if not raw:
        return True
    if _RANGE_OR_UNRESOLVED_RE.search(raw):
        return True
    if raw.lower() in {"unspecified", "latest", "unknown", "none", "null", "*"}:
        return True
    return False


def canonical_package_name(namespace: str, name: str) -> str:
    """Normalize package name according to ecosystem PURL rules (PyPI PEP 503)."""
    ns = str(namespace or "").strip().lower()
    raw = str(name or "").strip()
    if ns == "pypi":
        return re.sub(r"[-_.]+", "-", raw).lower()
    return raw


def canonical_namespace(eco_type: str, meta: str) -> str:
    """Normalize namespace/meta according to ecosystem PURL rules."""
    ns = str(eco_type or "").strip().lower()
    raw = str(meta or "").strip().strip("/")
    if not raw or ns == "pypi":
        return ""
    if ns == "npm":
        return raw if raw.startswith("@") else f"@{raw}"
    return raw


def canonical_release(namespace: str, release: str) -> str:
    """Return the package-manager canonical form for a release string.

    OSV records sometimes use Git tag notation such as v1.2.3 for ecosystems
    whose registries publish the package version as 1.2.3.
    """
    value = str(release or "").strip()
    ns = str(namespace or "").strip().lower()
    if ns in {"npm", "pypi"} and re.match(r"^[vV](?=\d)", value):
        return value[1:]
    return value


def _percent_decode_strict(value: str) -> str:
    """Decode percent-encoded UTF-8 string, raising ValueError on invalid % sequences."""
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "%":
            if i + 2 >= n or not all(c in "0123456789abcdefABCDEF" for c in value[i + 1 : i + 3]):
                raise ValueError(f"Malformed percent-encoding in PURL component: {value!r}")
            i += 3
        else:
            i += 1
    return unquote(value)


def _encode_path_segment(segment: str) -> str:
    # Per purl-spec, ':' and '/' and '@' are delimiters; '@' in npm scope is percent-encoded (%40)
    return quote(segment, safe="-._~")


def _encode_version(version: str) -> str:
    return quote(version, safe="-._~+")


def _encode_qualifier_value(val: str) -> str:
    return quote(val, safe="-._~:")


@dataclass(frozen=True)
class ParsedPurl:
    valid: bool
    purl: str
    package_purl: str
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: Dict[str, str] = field(default_factory=dict)
    subpath: str = ""
    is_versioned: bool = False
    is_range: bool = False
    error: Optional[str] = None

    @property
    def canonical_purl(self) -> str:
        return self.purl

    @property
    def raw(self) -> str:
        return self.purl

    @property
    def ecosystem(self) -> str:
        return ECOSYSTEM_LABELS.get(self.type, self.type or "Unknown")

    @property
    def library_coordinate(self) -> str:
        """Return display coordinate (`group:artifact` for maven, `@scope/name` for npm, etc.)."""
        if not self.name:
            return ""
        if self.type == "maven" and self.namespace:
            return f"{self.namespace}:{self.name}"
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    @property
    def key(self) -> str:
        """Return `<type>/<namespace>/<name>` or `<type>/<name>` matching JS catalog.mjs `parsed.key`."""
        if self.namespace:
            return f"{self.type}/{self.namespace}/{self.name}"
        return f"{self.type}/{self.name}"


def format_purl(
    eco_type: str,
    namespace: str,
    name: str,
    version: Optional[str] = None,
    qualifiers: Optional[Mapping[str, str]] = None,
    subpath: Optional[str] = None,
) -> str:
    """Serialize components into a canonical Package URL string."""
    t = str(eco_type or "").strip().lower()
    if not t or not PURL_TYPE_RE.match(t):
        raise ValueError(f"Invalid PURL type: {eco_type!r}")
    norm_ns = canonical_namespace(t, namespace)
    norm_name = canonical_package_name(t, name)
    if not norm_name:
        raise ValueError(f"Missing package name for PURL type {t!r}")
    if t == "maven" and not norm_ns:
        raise ValueError(f"Maven PURL requires groupId namespace for artifact {norm_name!r}")

    path_parts = []
    if norm_ns:
        for seg in norm_ns.split("/"):
            if seg:
                path_parts.append(_encode_path_segment(seg))
    path_parts.append(_encode_path_segment(norm_name))
    base = f"pkg:{t}/{'/'.join(path_parts)}"

    ver_str = str(version or "").strip() if version is not None else ""
    if ver_str:
        base = f"{base}@{_encode_version(ver_str)}"

    if qualifiers:
        q_items = []
        for k, v in sorted(qualifiers.items(), key=lambda item: str(item[0]).strip().lower()):
            k_norm = str(k or "").strip().lower()
            v_str = str(v or "").strip()
            if not k_norm or not v_str:
                continue
            if not QUALIFIER_KEY_RE.match(k_norm):
                raise ValueError(f"Invalid PURL qualifier key: {k!r}")
            q_items.append(f"{k_norm}={_encode_qualifier_value(v_str)}")
        if q_items:
            base = f"{base}?{'&'.join(q_items)}"

    sub_str = str(subpath or "").strip().strip("/")
    if sub_str:
        sub_segs = []
        for seg in sub_str.split("/"):
            if not seg or seg in {".", ".."}:
                raise ValueError(f"Invalid PURL subpath segment in {subpath!r}")
            sub_segs.append(_encode_path_segment(seg))
        if sub_segs:
            base = f"{base}#{'/'.join(sub_segs)}"

    return base


def parse_purl_spec(
    raw_value: Any,
    *,
    require_version: bool = False,
    reject_ranges: bool = False,
    allow_legacy_pipe: bool = False,
) -> ParsedPurl:
    """Parse and validate a Package URL string (and optionally a legacy pipe ID during transition)."""
    if not isinstance(raw_value, str) or not raw_value.strip():
        return ParsedPurl(
            valid=False,
            purl=str(raw_value or ""),
            package_purl="",
            type="unknown",
            namespace="",
            name="",
            version="",
            error="Missing product identifier",
        )

    raw = raw_value.strip()

    # Optional transition handling for legacy pipe-delimited library/package IDs
    if allow_legacy_pipe and not raw.startswith("pkg:") and "|" in raw:
        parts = raw.split("|")
        if len(parts) == 4:
            eco, meta, proj, rel = parts
            eco_l = eco.strip().lower()
            if eco_l in NON_PACKAGE_NAMESPACES:
                return ParsedPurl(
                    valid=False,
                    purl=raw,
                    package_purl="",
                    type=eco_l,
                    namespace=meta.strip(),
                    name=proj.strip(),
                    version=rel.strip(),
                    error=f"Non-package identifier cannot be treated as a PURL: {raw}",
                )
            try:
                ver_p = format_purl(eco_l, meta, proj, rel)
                return parse_purl_spec(ver_p, require_version=require_version, reject_ranges=reject_ranges)
            except ValueError as exc:
                return ParsedPurl(
                    valid=False,
                    purl=raw,
                    package_purl="",
                    type=eco_l or "other",
                    namespace=meta,
                    name=proj,
                    version=rel,
                    error=str(exc),
                )
        elif len(parts) == 3 and not require_version:
            eco, meta, proj = parts
            eco_l = eco.strip().lower()
            if eco_l in NON_PACKAGE_NAMESPACES:
                return ParsedPurl(
                    valid=False,
                    purl=raw,
                    package_purl="",
                    type=eco_l,
                    namespace=meta.strip(),
                    name=proj.strip(),
                    version="",
                    error=f"Non-package identifier cannot be treated as a PURL: {raw}",
                )
            try:
                pkg_p = format_purl(eco_l, meta, proj, None)
                return parse_purl_spec(pkg_p, require_version=False, reject_ranges=reject_ranges)
            except ValueError as exc:
                return ParsedPurl(
                    valid=False,
                    purl=raw,
                    package_purl="",
                    type=eco_l or "other",
                    namespace=meta,
                    name=proj,
                    version="",
                    error=str(exc),
                )

    if not raw.startswith("pkg:"):
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type="other",
            namespace="",
            name=raw,
            version="",
            error=f"Unsupported or non-PURL product identifier: {raw}",
        )

    remainder = raw[4:]
    # Strip leading slashes after scheme if malformed like pkg://maven/... -> reject per strict spec
    if remainder.startswith("/"):
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type="other",
            namespace="",
            name=raw,
            version="",
            error=f"Invalid PURL authority slashes after pkg: scheme: {raw}",
        )

    # 1. Subpath from right
    subpath = ""
    if "#" in remainder:
        remainder, raw_subpath = remainder.split("#", 1)
        raw_subpath = raw_subpath.strip("/")
        if raw_subpath:
            decoded_segs = []
            for seg in raw_subpath.split("/"):
                try:
                    dec = _percent_decode_strict(seg)
                except ValueError as exc:
                    return ParsedPurl(
                        valid=False, purl=raw, package_purl="", type="other", namespace="", name="", version="", error=str(exc)
                    )
                if not dec or dec in {".", ".."} or "/" in dec:
                    return ParsedPurl(
                        valid=False,
                        purl=raw,
                        package_purl="",
                        type="other",
                        namespace="",
                        name="",
                        version="",
                        error=f"Invalid subpath in PURL: {raw}",
                    )
                decoded_segs.append(dec)
            subpath = "/".join(decoded_segs)

    # 2. Qualifiers from right
    qualifiers: Dict[str, str] = {}
    if "?" in remainder:
        remainder, raw_qs = remainder.split("?", 1)
        if raw_qs:
            for pair in raw_qs.split("&"):
                if not pair:
                    continue
                if "=" not in pair:
                    return ParsedPurl(
                        valid=False,
                        purl=raw,
                        package_purl="",
                        type="other",
                        namespace="",
                        name="",
                        version="",
                        error=f"Malformed qualifier in PURL: {raw}",
                    )
                k_raw, v_raw = pair.split("=", 1)
                k_norm = k_raw.strip().lower()
                if not k_norm or not QUALIFIER_KEY_RE.match(k_norm):
                    return ParsedPurl(
                        valid=False,
                        purl=raw,
                        package_purl="",
                        type="other",
                        namespace="",
                        name="",
                        version="",
                        error=f"Invalid qualifier key {k_raw!r} in PURL: {raw}",
                    )
                try:
                    v_dec = _percent_decode_strict(v_raw).strip()
                except ValueError as exc:
                    return ParsedPurl(
                        valid=False, purl=raw, package_purl="", type="other", namespace="", name="", version="", error=str(exc)
                    )
                if v_dec:
                    qualifiers[k_norm] = v_dec

    # 3. Type from left
    if "/" not in remainder:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type="other",
            namespace="",
            name=raw,
            version="",
            error=f"Missing type/name separator in PURL: {raw}",
        )
    raw_type, path_and_ver = remainder.split("/", 1)
    eco_type = raw_type.strip().lower()
    if not eco_type or not PURL_TYPE_RE.match(eco_type) or not path_and_ver:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type="other",
            namespace="",
            name=raw,
            version="",
            error=f"Invalid ecosystem type in PURL: {raw}",
        )

    # 4. Version from right
    at_idx = path_and_ver.rfind("@")
    has_at = at_idx >= 0
    if has_at:
        raw_path = path_and_ver[:at_idx]
        raw_ver = path_and_ver[at_idx + 1 :]
        if not raw_ver:
            return ParsedPurl(
                valid=False,
                purl=raw,
                package_purl="",
                type=eco_type,
                namespace="",
                name="",
                version="",
                error=f"Empty version after '@' in PURL: {raw}",
            )
        try:
            version = _percent_decode_strict(raw_ver).strip()
        except ValueError as exc:
            return ParsedPurl(
                valid=False, purl=raw, package_purl="", type=eco_type, namespace="", name="", version="", error=str(exc)
            )
    else:
        raw_path = path_and_ver
        version = ""

    # 5. Namespace and Name
    if not raw_path or raw_path.startswith("/") or raw_path.endswith("/") or "//" in raw_path:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type=eco_type,
            namespace="",
            name="",
            version=version,
            error=f"Malformed package path in PURL: {raw}",
        )
    raw_segments = raw_path.split("/")
    decoded_segments = []
    for seg in raw_segments:
        try:
            dec = _percent_decode_strict(seg).strip()
        except ValueError as exc:
            return ParsedPurl(
                valid=False, purl=raw, package_purl="", type=eco_type, namespace="", name="", version=version, error=str(exc)
            )
        if not dec or "/" in dec:
            return ParsedPurl(
                valid=False,
                purl=raw,
                package_purl="",
                type=eco_type,
                namespace="",
                name="",
                version=version,
                error=f"Invalid path segment in PURL: {raw}",
            )
        decoded_segments.append(dec)

    raw_name = decoded_segments[-1]
    raw_ns = "/".join(decoded_segments[:-1])

    if eco_type == "maven" and not raw_ns:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type=eco_type,
            namespace="",
            name=raw_name,
            version=version,
            error=f"Maven PURL requires both groupId namespace and artifactId name: {raw}",
        )
    if eco_type == "npm" and raw_ns and (not raw_ns.startswith("@") or "/" in raw_ns):
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl="",
            type=eco_type,
            namespace=raw_ns,
            name=raw_name,
            version=version,
            error=f"npm PURL namespace must be a single @scope segment: {raw}",
        )

    norm_ns = canonical_namespace(eco_type, raw_ns)
    norm_name = canonical_package_name(eco_type, raw_name)
    is_range = is_version_range_or_unresolved(version) if version else False

    if require_version and not version:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl=format_purl(eco_type, norm_ns, norm_name),
            type=eco_type,
            namespace=norm_ns,
            name=norm_name,
            version="",
            qualifiers=qualifiers,
            subpath=subpath,
            is_versioned=False,
            is_range=False,
            error=f"Missing version in product PURL: {raw}",
        )

    if reject_ranges and version and is_range:
        return ParsedPurl(
            valid=False,
            purl=raw,
            package_purl=format_purl(eco_type, norm_ns, norm_name),
            type=eco_type,
            namespace=norm_ns,
            name=norm_name,
            version=version,
            qualifiers=qualifiers,
            subpath=subpath,
            is_versioned=True,
            is_range=True,
            error=f"Version range or unresolved expression cannot be used as an exact artifact PURL: {raw}",
        )

    pkg_purl = format_purl(eco_type, norm_ns, norm_name, None)
    canonical_full = format_purl(eco_type, norm_ns, norm_name, version if version else None, qualifiers, subpath)

    return ParsedPurl(
        valid=True,
        purl=canonical_full,
        package_purl=pkg_purl,
        type=eco_type,
        namespace=norm_ns,
        name=norm_name,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
        is_versioned=bool(version),
        is_range=is_range,
        error=None,
    )


def split_coords(namespace: str, name: str) -> Tuple[str, str, str]:
    """Split an ecosystem + package name into (namespace, meta, proj)."""
    ns = str(namespace or "").strip().lower()
    raw = str(name or "").strip()
    if ns == "maven" and ":" in raw:
        meta, proj = raw.split(":", 1)
    elif ns == "maven" and "/" in raw:
        meta, proj = raw.split("/", 1)
    elif ns == "npm" and raw.startswith("@") and "/" in raw:
        meta, proj = raw.split("/", 1)
    elif ns in {"rpm", "deb", "apk", "oci", "docker"} and "/" in raw:
        meta, proj = raw.rsplit("/", 1)
    else:
        meta = ""
        proj = raw
    return ns, canonical_namespace(ns, meta), canonical_package_name(ns, proj)


def make_package_id(namespace: str, meta: str, proj: str) -> str:
    """Construct a canonical versionless package PURL (`pkg:<type>/<namespace>/<name>`)."""
    return format_purl(namespace, meta, proj, None)


def make_library_id(
    namespace: str,
    meta: str,
    proj: str,
    release: str,
    qualifiers: Optional[Mapping[str, str]] = None,
    subpath: Optional[str] = None,
) -> str:
    """Construct a canonical versioned library PURL (`pkg:<type>/<namespace>/<name>@<release>`)."""
    rel = str(release or "").strip()
    if not rel:
        raise ValueError(f"Release version is required to construct versioned library PURL for {namespace}/{meta}/{proj}")
    return format_purl(namespace, meta, proj, rel, qualifiers=qualifiers, subpath=subpath)


def parse_library_id(library_id: str, *, strict: bool = False) -> Tuple[str, str, str, str]:
    """Parse a canonical PURL or legacy 4-part pipe library ID into `(namespace, meta, proj, release)`."""
    raw = str(library_id or "").strip()
    if not raw:
        if strict:
            raise ValueError("Empty library identifier")
        return ("", "", "", "")
    if raw.startswith("pkg:"):
        parsed = parse_purl_spec(raw, require_version=True, allow_legacy_pipe=False)
        if not parsed.valid:
            if strict:
                raise ValueError(parsed.error or f"Invalid library PURL: {raw!r}")
            return ("", "", "", "")
        return parsed.type, parsed.namespace, parsed.name, parsed.version

    if "|" in raw:
        parts = raw.split("|")
        if len(parts) != 4:
            if strict:
                raise ValueError(f"Legacy pipe library ID must have 4 segments (namespace|meta|proj|release): {raw!r}")
            return ("", "", "", "")
        ns, meta, proj, release = parts
        ns_l = ns.strip().lower()
        if not ns_l or ns_l in NON_PACKAGE_NAMESPACES:
            if strict:
                raise ValueError(f"Identifier {raw!r} is not a package library ID")
            return ("", "", "", "")
        norm_meta = canonical_namespace(ns_l, meta)
        norm_proj = canonical_package_name(ns_l, proj)
        if not norm_proj or not release.strip():
            if strict:
                raise ValueError(f"Incomplete legacy pipe library ID: {raw!r}")
            return ("", "", "", "")
        return ns_l, norm_meta, norm_proj, release.strip()

    if strict:
        raise ValueError(
            f"Unsupported or ambiguous package coordinate {raw!r}: expected standard PURL ('pkg:...') "
            "or legacy 4-part pipe ID ('namespace|meta|proj|release')."
        )
    return ("", "", "", "")


def parse_package_id(package_id: str, *, strict: bool = False) -> Tuple[str, str, str]:
    """Parse a versionless package PURL, versioned artifact PURL, or legacy pipe ID into `(namespace, meta, proj)`."""
    raw = str(package_id or "").strip()
    if not raw:
        if strict:
            raise ValueError("Empty package identifier")
        return ("", "", "")
    if raw.startswith("pkg:"):
        parsed = parse_purl_spec(raw, require_version=False, allow_legacy_pipe=False)
        if not parsed.valid:
            if strict:
                raise ValueError(parsed.error or f"Invalid package PURL: {raw!r}")
            return ("", "", "")
        return parsed.type, parsed.namespace, parsed.name

    if "|" in raw:
        parts = raw.split("|")
        if len(parts) in (3, 4):
            ns, meta, proj = parts[0], parts[1], parts[2]
            ns_l = ns.strip().lower()
            if not ns_l or ns_l in NON_PACKAGE_NAMESPACES:
                if strict:
                    raise ValueError(f"Identifier {raw!r} is not a package ID")
                return ("", "", "")
            norm_meta = canonical_namespace(ns_l, meta)
            norm_proj = canonical_package_name(ns_l, proj)
            if not norm_proj:
                if strict:
                    raise ValueError(f"Incomplete legacy package ID: {raw!r}")
                return ("", "", "")
            return ns_l, norm_meta, norm_proj

    if strict:
        raise ValueError(
            f"Unsupported or ambiguous package identifier {raw!r}: expected standard PURL ('pkg:...') "
            "or legacy pipe ID ('namespace|meta|proj')."
        )
    return ("", "", "")


def canonical_library_id(library_id: str, *, strict: bool = False) -> str:
    """Normalize a PURL or legacy pipe library ID into a canonical versioned PURL with canonical release."""
    raw = str(library_id or "").strip()
    if raw.startswith("pkg:"):
        parsed = parse_purl_spec(raw, require_version=True, allow_legacy_pipe=False)
        if not parsed.valid:
            if strict:
                raise ValueError(parsed.error or f"Invalid library PURL: {raw!r}")
            return ""
        norm_rel = canonical_release(parsed.type, parsed.version)
        return format_purl(
            parsed.type,
            parsed.namespace,
            parsed.name,
            norm_rel,
            qualifiers=parsed.qualifiers,
            subpath=parsed.subpath,
        )
    namespace, meta, proj, release = parse_library_id(raw, strict=strict)
    if not namespace or not proj or not release:
        return ""
    return make_library_id(namespace, meta, proj, canonical_release(namespace, release))


def canonical_package_id(package_id: str, *, strict: bool = False) -> str:
    """Normalize a versionless/versioned PURL or legacy pipe package ID into a canonical versionless PURL."""
    namespace, meta, proj = parse_package_id(package_id, strict=strict)
    if not namespace or not proj:
        return ""
    return make_package_id(namespace, meta, proj)


def same_artifact_purl(left: str, right: str) -> bool:
    """Return True only when both strings are valid versioned PURLs for the exact same artifact (including qualifiers/subpath)."""
    a = parse_purl_spec(left, require_version=True, reject_ranges=True, allow_legacy_pipe=True)
    b = parse_purl_spec(right, require_version=True, reject_ranges=True, allow_legacy_pipe=True)
    if not a.valid or not b.valid:
        return False
    return a.purl == b.purl


def same_package_purl(left: str, right: str) -> bool:
    """Return True when both identifiers refer to the same versionless package `(type, namespace, name)`."""
    try:
        return canonical_package_id(left) == canonical_package_id(right)
    except ValueError:
        return False

#!/usr/bin/env python3
"""Shared helpers for Risk Navigator data pipeline."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_GA_SUFFIX_RE = re.compile(r"(?:\.|-)(Final|RELEASE|GA|jre\d*)$", re.IGNORECASE)
_NUMERIC_VER_RE = re.compile(r"^\d+(?:\.\d+)*$")
NON_GA_HINT_RE = re.compile(
    r"(?i)(?:^|[.-])(snapshot|alpha|beta|rc\d*|cr\d*|m\d+|milestone|preview|ea|atlassian|cloudera|redhat|rhel|ppa)(?:$|[.-])"
)


def to_ascii(text: str) -> str:
    """Normalize generated text for strict YAML consumers."""

    replacements = {
        "\u2014": "--",
        "\u2013": "--",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u00a0": " ",
        "\u2192": "->",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    out = []
    for ch in text:
        code = ord(ch)
        if code in (9, 10, 13) or 32 <= code <= 126:
            out.append(ch)
        else:
            out.append("?")
    return "".join(out)


def slugify(text: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return base or "scope"


def split_coords(namespace: str, name: str) -> Tuple[str, str, str]:
    ns = namespace.lower()
    if ns == "maven" and ":" in name:
        meta, proj = name.split(":", 1)
    elif ns == "npm" and name.startswith("@") and "/" in name:
        meta, proj = name.split("/", 1)
    elif ns == "rpm" and "/" in name:
        meta, proj = name.split("/", 1)
    else:
        meta = ""
        proj = name
    return ns, meta, proj


def make_library_id(namespace: str, meta: str, proj: str, release: str) -> str:
    return f"{namespace}|{meta}|{proj}|{release}"


def canonical_release(namespace: str, release: str) -> str:
    """Return the package-manager canonical form for a release string.

    OSV records sometimes use Git tag notation such as v1.2.3 for ecosystems
    whose registries publish the package version as 1.2.3. Normalize that at
    ingestion/build boundaries so version chains do not split the same release
    into duplicate rows with conflicting vulnerability metadata.
    """

    value = str(release or "").strip()
    ns = str(namespace or "").lower()
    if ns in {"npm", "pypi"} and re.match(r"^[vV](?=\d)", value):
        return value[1:]
    return value


def canonical_library_id(library_id: str) -> str:
    namespace, meta, proj, release = parse_library_id(library_id)
    return make_library_id(namespace, meta, proj, canonical_release(namespace, release))


def parse_library_id(library_id: str) -> Tuple[str, str, str, str]:
    namespace, meta, proj, release = library_id.split("|", 3)
    return namespace, meta, proj, release


def is_ga_release(release: str) -> bool:
    raw = release.strip()
    if not raw or NON_GA_HINT_RE.search(raw):
        return False
    base = _GA_SUFFIX_RE.sub("", raw)
    return bool(_NUMERIC_VER_RE.match(base))


def _numeric_prefix_tokens(release: str) -> Optional[Tuple[int, ...]]:
    match = re.match(r"^(\d+(?:\.\d+)*)", release.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _pad(tokens: Sequence[int], length: int = 4) -> Tuple[int, ...]:
    vals = list(tokens[:length])
    while len(vals) < length:
        vals.append(0)
    return tuple(vals)


def compare_versions(namespace: str, left: str, right: str) -> Optional[int]:
    """Best-effort comparator across maven/npm/pypi/rpm strings.

    Returns:
      -1 if left < right
       0 if equal
       1 if left > right
       None if unparseable
    """

    ns = namespace.lower()
    if ns == "rpm":
        return compare_rpm_versions(left, right)

    lt = _numeric_prefix_tokens(left)
    rt = _numeric_prefix_tokens(right)
    if lt is None or rt is None:
        return None
    lpad = _pad(lt, 6)
    rpad = _pad(rt, 6)
    if lpad < rpad:
        return -1
    if lpad > rpad:
        return 1
    # prefer GA over non-GA if numeric core ties
    l_ga = is_ga_release(left)
    r_ga = is_ga_release(right)
    if l_ga and not r_ga:
        return 1
    if r_ga and not l_ga:
        return -1
    return 0


def compare_rpm_versions(left: str, right: str) -> Optional[int]:
    """Simplified RPM EVR comparator for sample datasets."""

    def parse_evr(value: str) -> Optional[Tuple[int, Tuple[int, ...], Tuple[int, ...]]]:
        v = value.strip()
        if not v:
            return None
        epoch = 0
        rest = v
        if ":" in rest:
            ep, rest = rest.split(":", 1)
            if not ep.isdigit():
                return None
            epoch = int(ep)
        if "-" in rest:
            version, rel = rest.split("-", 1)
        else:
            version, rel = rest, "0"
        vt = _numeric_prefix_tokens(version)
        rt = _numeric_prefix_tokens(rel)
        if vt is None:
            return None
        if rt is None:
            rt = (0,)
        return (epoch, _pad(vt, 6), _pad(rt, 6))

    lp = parse_evr(left)
    rp = parse_evr(right)
    if lp is None or rp is None:
        return None
    if lp < rp:
        return -1
    if lp > rp:
        return 1
    return 0


def classify_distance(current_release: str, safe_release: str, namespace: str = "maven") -> str:
    cur = _numeric_prefix_tokens(current_release)
    saf = _numeric_prefix_tokens(safe_release)
    if cur is None or saf is None or len(cur) == 0 or len(saf) == 0:
        return "UNKNOWN"

    cur_major, cur_minor, cur_patch = _pad(cur, 3)
    saf_major, saf_minor, saf_patch = _pad(saf, 3)

    if saf_major != cur_major:
        return "MAJOR"
    if saf_minor != cur_minor:
        return "MINOR"
    if saf_patch != cur_patch:
        return "PATCH"
    return "PATCH"


@dataclass
class VersionCandidate:
    release: str
    max_cvss: float


def find_nearest_safe(
    namespace: str,
    current_release: str,
    version_chain: Sequence[Dict[str, object]],
) -> Tuple[Optional[str], Optional[str], str]:
    """Find nearest GA safe version and max patch in same minor.

    Returns (nearest_safe, max_safe_patch_same_minor, distance).
    """

    candidates: List[VersionCandidate] = []
    for row in version_chain:
        release = str(row.get("release", "")).strip()
        if not release:
            continue
        max_cvss = float(row.get("max_cvss", 0.0) or 0.0)
        if max_cvss >= 7.0:
            continue
        if not is_ga_release(release):
            continue
        cmpv = compare_versions(namespace, release, current_release)
        if cmpv is None or cmpv <= 0:
            continue
        candidates.append(VersionCandidate(release=release, max_cvss=max_cvss))

    if not candidates:
        cur_ok = _numeric_prefix_tokens(current_release) is not None
        return (None, None, "DEAD_END" if cur_ok else "UNKNOWN")

    candidates.sort(key=lambda row: _pad(_numeric_prefix_tokens(row.release) or (), 6))
    nearest = candidates[0].release
    distance = classify_distance(current_release, nearest, namespace=namespace)

    nearest_tokens = _numeric_prefix_tokens(nearest)
    max_patch = nearest
    if nearest_tokens is not None:
        n_major, n_minor, _ = _pad(nearest_tokens, 3)
        same_minor: List[str] = []
        for row in candidates:
            tok = _numeric_prefix_tokens(row.release)
            if tok is None:
                continue
            major, minor, _ = _pad(tok, 3)
            if major == n_major and minor == n_minor:
                same_minor.append(row.release)
        if same_minor:
            same_minor.sort(key=lambda rel: _pad(_numeric_prefix_tokens(rel) or (), 6))
            max_patch = same_minor[-1]

    return (nearest, max_patch, distance)


def risk_signal(max_cvss: float, consumers: int, kev: bool = False, epss_max: float = 0.0) -> float:
    import math

    score = max_cvss * math.log(consumers + 1)
    if kev:
        score *= 3.0
    score *= 1.0 + max(0.0, epss_max)
    return score

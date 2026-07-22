#!/usr/bin/env python3
"""Describe compatibility risk between two Codegenome graph exports."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

PUBLIC_KINDS = {"class", "function", "method", "interface", "enum", "type", "component"}
BREAKING_DISTANCE = {"MAJOR"}
REVIEW_DISTANCE = {"MINOR"}
DISTANCES = {"PATCH", "MINOR", "MAJOR", "DEAD_END", "UNKNOWN"}
CLASSIFICATIONS = {
    "PATCH_SAFE",
    "MINOR_REQUIRES_REVIEW",
    "LIKELY_BREAKING",
    "BACKPATCH_LIKELY",
    "BACKPATCH_PROBABLE",
    "DEAD_END",
}


@dataclass(frozen=True)
class PublicSymbol:
    key: str
    node_id: str
    name: str
    kind: str
    file_path: str
    complexity: int
    start_line: Optional[int]
    end_line: Optional[int]
    docstring: str

    @classmethod
    def from_node(cls, node: Dict[str, object]) -> "PublicSymbol":
        name = str(node.get("qualified_name") or node.get("name") or "").strip()
        return cls(
            key=name,
            node_id=str(node.get("id") or node.get("node_id") or ""),
            name=str(node.get("name") or name),
            kind=str(node.get("kind") or ""),
            file_path=str(node.get("file_path") or ""),
            complexity=int(node.get("complexity") or 0),
            start_line=_optional_int(node.get("start_line")),
            end_line=_optional_int(node.get("end_line")),
            docstring=str(node.get("docstring") or ""),
        )

    def changed_compared_to(self, other: "PublicSymbol") -> bool:
        return (
            self.kind != other.kind
            or self.complexity != other.complexity
            or self.start_line != other.start_line
            or self.end_line != other.end_line
            or self.docstring != other.docstring
        )

    def labels(self) -> Set[str]:
        return {self.key, self.name, self.node_id, f"{self.file_path}:{self.name}"} - {""}


@dataclass(frozen=True)
class GraphSnapshot:
    path: Path
    symbols: Dict[str, PublicSymbol]
    files: Set[str]
    imports: Set[str]
    entry_points: Set[str]
    circular_dependencies: Tuple[object, ...]


def _optional_int(value: object) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _node_id(node: Dict[str, object]) -> str:
    return str(node.get("id") or node.get("node_id") or "")


def _is_generated_or_test(file_path: str) -> bool:
    path = file_path.replace("\\", "/")
    return (
        "/node_modules/" in f"/{path}/"
        or path.startswith("node_modules/")
        or path.startswith("tests/")
        or "/tests/" in path
        or path.endswith(".test.js")
        or path.endswith("_test.py")
    )


def _is_public_symbol(node: Dict[str, object]) -> bool:
    if str(node.get("node_type") or "") != "symbol":
        return False
    kind = str(node.get("kind") or "").lower()
    if kind and kind not in PUBLIC_KINDS:
        return False
    name = str(node.get("qualified_name") or node.get("name") or "").strip()
    if not name:
        return False
    leaf_name = name.rsplit(".", 1)[-1]
    if leaf_name.startswith("_"):
        return False
    file_path = str(node.get("file_path") or "")
    return not _is_generated_or_test(file_path)


def _import_name(node: Dict[str, object]) -> str:
    node_id = _node_id(node)
    if ":" in node_id:
        return node_id.rsplit(":", 1)[-1]
    return str(node.get("name") or node_id)


def load_graph(path: Path) -> GraphSnapshot:
    payload = json.loads(path.read_text(encoding="utf-8"))
    nodes = payload.get("nodes", [])
    if not isinstance(nodes, list):
        raise ValueError(f"{path} does not look like a Codegenome JSON export: nodes must be a list")

    symbols: Dict[str, PublicSymbol] = {}
    files: Set[str] = set()
    imports: Set[str] = set()
    for raw_node in nodes:
        if not isinstance(raw_node, dict):
            continue
        node_type = str(raw_node.get("node_type") or "")
        file_path = str(raw_node.get("file_path") or "")
        if node_type == "file" and file_path:
            files.add(file_path)
        elif node_type == "import":
            imports.add(_import_name(raw_node))
        elif _is_public_symbol(raw_node):
            symbol = PublicSymbol.from_node(raw_node)
            symbols[symbol.key] = symbol

    intelligence = payload.get("intelligence", {})
    if not isinstance(intelligence, dict):
        intelligence = {}
    entry_points = intelligence.get("entry_points", [])
    circular_dependencies = intelligence.get("circular_dependencies", [])

    return GraphSnapshot(
        path=path,
        symbols=symbols,
        files=files,
        imports=imports,
        entry_points=set(str(item) for item in entry_points if item),
        circular_dependencies=tuple(circular_dependencies if isinstance(circular_dependencies, list) else []),
    )


def load_usage_labels(path: Optional[Path]) -> Set[str]:
    if path is None:
        return set()
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")}
    out: Set[str] = set()
    _collect_strings(payload, out)
    return out


def _collect_strings(value: object, out: Set[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            out.add(value.strip())
    elif isinstance(value, dict):
        for key, item in value.items():
            _collect_strings(key, out)
            _collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)


def _symbol_rows(symbols: Iterable[PublicSymbol], limit: int) -> List[Dict[str, object]]:
    return [
        {
            "symbol": sym.key,
            "name": sym.name,
            "kind": sym.kind,
            "file_path": sym.file_path,
            "complexity": sym.complexity,
            "start_line": sym.start_line,
            "end_line": sym.end_line,
        }
        for sym in sorted(symbols, key=lambda item: (item.file_path, item.key))[:limit]
    ]


def _intersects_usage(symbol: PublicSymbol, usage_labels: Set[str]) -> bool:
    return bool(symbol.labels() & usage_labels)


def diff_graphs(
    vulnerable: GraphSnapshot,
    candidate: GraphSnapshot,
    usage_labels: Set[str],
    distance: str,
    high_complexity_threshold: int,
    limit: int,
) -> Dict[str, object]:
    old_keys = set(vulnerable.symbols)
    new_keys = set(candidate.symbols)
    removed = [vulnerable.symbols[key] for key in sorted(old_keys - new_keys)]
    added = [candidate.symbols[key] for key in sorted(new_keys - old_keys)]

    moved: List[Tuple[PublicSymbol, PublicSymbol]] = []
    changed: List[Tuple[PublicSymbol, PublicSymbol]] = []
    for key in sorted(old_keys & new_keys):
        old = vulnerable.symbols[key]
        new = candidate.symbols[key]
        if old.file_path != new.file_path:
            moved.append((old, new))
        if new.changed_compared_to(old):
            changed.append((old, new))

    usage_impacts_by_key = {
        sym.key: sym
        for sym in removed
        if _intersects_usage(sym, usage_labels)
    }
    for old, _new in moved + changed:
        if _intersects_usage(old, usage_labels):
            usage_impacts_by_key[old.key] = old
    usage_impacts = list(usage_impacts_by_key.values())

    high_complexity_by_key = {
        new.key: new
        for _old, new in changed + moved
        if new.complexity >= high_complexity_threshold
    }
    high_complexity_changed = list(high_complexity_by_key.values())
    new_cycles = max(0, len(candidate.circular_dependencies) - len(vulnerable.circular_dependencies))

    classification, reasons = classify(
        distance=distance,
        removed_public_count=len(removed),
        usage_impact_count=len(usage_impacts),
        moved_public_count=len(moved),
        changed_public_count=len(changed),
        high_complexity_changed_count=len(high_complexity_changed),
        new_circular_dependency_count=new_cycles,
    )

    return {
        "classification": classification,
        "classification_reasons": reasons,
        "distance_to_safe": distance,
        "summary": {
            "removed_public_symbols": len(removed),
            "added_public_symbols": len(added),
            "moved_public_symbols": len(moved),
            "changed_public_symbols": len(changed),
            "consumer_usage_impacts": len(usage_impacts),
            "removed_imports": len(vulnerable.imports - candidate.imports),
            "added_imports": len(candidate.imports - vulnerable.imports),
            "removed_files": len(vulnerable.files - candidate.files),
            "added_files": len(candidate.files - vulnerable.files),
            "new_circular_dependency_count": new_cycles,
            "high_complexity_changed_symbols": len(high_complexity_changed),
        },
        "removed_public_symbols": _symbol_rows(removed, limit),
        "added_public_symbols": _symbol_rows(added, limit),
        "moved_public_symbols": [
            {
                "symbol": old.key,
                "from_file_path": old.file_path,
                "to_file_path": new.file_path,
                "complexity": new.complexity,
            }
            for old, new in moved[:limit]
        ],
        "changed_public_symbols": [
            {
                "symbol": old.key,
                "file_path": new.file_path,
                "old_complexity": old.complexity,
                "new_complexity": new.complexity,
                "old_span": [old.start_line, old.end_line],
                "new_span": [new.start_line, new.end_line],
            }
            for old, new in changed[:limit]
        ],
        "consumer_usage_impacts": _symbol_rows(usage_impacts, limit),
        "high_complexity_changed_symbols": _symbol_rows(high_complexity_changed, limit),
        "removed_imports": sorted(vulnerable.imports - candidate.imports)[:limit],
        "added_imports": sorted(candidate.imports - vulnerable.imports)[:limit],
    }


def classify(
    distance: str,
    removed_public_count: int,
    usage_impact_count: int,
    moved_public_count: int,
    changed_public_count: int,
    high_complexity_changed_count: int,
    new_circular_dependency_count: int,
) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    normalized_distance = distance.upper()

    if normalized_distance == "DEAD_END":
        return "DEAD_END", ["safe-version walker found no GA below-threshold candidate"]

    breaking_signal = (
        usage_impact_count > 0
        or removed_public_count > 0
        or moved_public_count > 0
        or new_circular_dependency_count > 0
    )
    review_signal = changed_public_count > 0 or high_complexity_changed_count > 0

    if usage_impact_count:
        reasons.append(f"{usage_impact_count} changed/removed symbols intersect consumer usage")
    if removed_public_count:
        reasons.append(f"{removed_public_count} public symbols are removed")
    if moved_public_count:
        reasons.append(f"{moved_public_count} public symbols moved packages/files")
    if new_circular_dependency_count:
        reasons.append(f"{new_circular_dependency_count} new circular dependency groups appeared")
    if high_complexity_changed_count:
        reasons.append(f"{high_complexity_changed_count} changed symbols are high-complexity")

    if breaking_signal and normalized_distance in BREAKING_DISTANCE:
        reasons.append("nearest safe version is major-only, so backpatch is the primary remediation path to evaluate")
        return "BACKPATCH_PROBABLE", reasons
    if breaking_signal and normalized_distance in REVIEW_DISTANCE:
        reasons.append("nearest safe version is minor-only and graph diff shows compatibility risk")
        return "BACKPATCH_LIKELY", reasons
    if breaking_signal:
        return "LIKELY_BREAKING", reasons

    if normalized_distance in BREAKING_DISTANCE:
        return "BACKPATCH_PROBABLE", ["nearest safe version is major-only"]
    if normalized_distance in REVIEW_DISTANCE:
        return "MINOR_REQUIRES_REVIEW", reasons or ["nearest safe version requires a minor upgrade"]
    if review_signal:
        return "MINOR_REQUIRES_REVIEW", reasons or ["public symbols changed but no removals or usage impacts were found"]
    return "PATCH_SAFE", ["no public removals, package moves, usage impacts, or new cycles found"]


def render_markdown(report: Dict[str, object], package: str, current: str, candidate: str, cves: Sequence[str]) -> str:
    summary = report["summary"]
    assert isinstance(summary, dict)
    reasons = report.get("classification_reasons", [])
    lines = [
        f"# CVE Patch Description: {package}",
        "",
        f"- Current release: `{current or '-'}`",
        f"- Candidate safe release: `{candidate or '-'}`",
        f"- CVEs: `{', '.join(cves) if cves else '-'}`",
        f"- Classification: `{report['classification']}`",
        f"- Safe-version distance: `{report['distance_to_safe']}`",
        "",
        "## Codegenome Diff Summary",
        "",
    ]
    for key in (
        "removed_public_symbols",
        "moved_public_symbols",
        "changed_public_symbols",
        "consumer_usage_impacts",
        "high_complexity_changed_symbols",
        "new_circular_dependency_count",
        "removed_imports",
        "added_imports",
    ):
        lines.append(f"- {key}: `{summary.get(key, 0)}`")
    lines.extend(["", "## Rationale", ""])
    for reason in reasons:
        lines.append(f"- {reason}")
    lines.extend(["", "## Next Checks", ""])
    lines.append("- Review listed removed/moved symbols against direct and transitive consumers.")
    lines.append("- Run dependency-specific tests for consumers that touch impacted symbols.")
    lines.append("- If classified as `BACKPATCH_*`, compare backpatch effort against the upgrade migration.")
    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vulnerable-graph", type=Path, required=True, help="Codegenome JSON export for the vulnerable version")
    parser.add_argument("--candidate-graph", type=Path, required=True, help="Codegenome JSON export for the candidate safe version")
    parser.add_argument("--consumer-usage", type=Path, help="Optional JSON or newline-delimited symbols used by consumers")
    parser.add_argument("--distance", choices=sorted(DISTANCES), default="UNKNOWN", help="Safe-version distance from find_nearest_safe")
    parser.add_argument("--package", default="", help="Package coordinate for report context")
    parser.add_argument("--current-release", default="", help="Current vulnerable release")
    parser.add_argument("--candidate-release", default="", help="Candidate safe release")
    parser.add_argument("--cve", action="append", default=[], help="CVE id; repeat for multiple CVEs")
    parser.add_argument("--high-complexity-threshold", type=int, default=10)
    parser.add_argument("--limit", type=int, default=25, help="Maximum rows to include per detail section")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    vulnerable = load_graph(args.vulnerable_graph)
    candidate = load_graph(args.candidate_graph)
    usage = load_usage_labels(args.consumer_usage)
    report = diff_graphs(
        vulnerable=vulnerable,
        candidate=candidate,
        usage_labels=usage,
        distance=args.distance,
        high_complexity_threshold=args.high_complexity_threshold,
        limit=args.limit,
    )
    report["package"] = args.package
    report["current_release"] = args.current_release
    report["candidate_release"] = args.candidate_release
    report["cves"] = args.cve

    if args.format == "markdown":
        print(render_markdown(report, args.package, args.current_release, args.candidate_release, args.cve))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

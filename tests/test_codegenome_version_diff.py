import json
from pathlib import Path

from codegenome_version_diff import diff_graphs, load_graph, load_usage_labels


def write_graph(path: Path, nodes, circular_dependencies=None):
    path.write_text(
        json.dumps(
            {
                "nodes": nodes,
                "edges": [],
                "intelligence": {
                    "entry_points": [],
                    "circular_dependencies": circular_dependencies or [],
                },
                "metadata": {},
            }
        )
    )


def symbol(name, file_path="pkg/api.py", complexity=1, start_line=1, end_line=3):
    return {
        "id": f"symbol:{file_path}:{name}",
        "node_type": "symbol",
        "kind": "function",
        "name": name,
        "qualified_name": name,
        "file_path": file_path,
        "complexity": complexity,
        "start_line": start_line,
        "end_line": end_line,
    }


def test_patch_safe_when_no_public_api_changes(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    nodes = [symbol("parse"), {"id": "file:pkg/api.py", "node_type": "file", "file_path": "pkg/api.py"}]
    write_graph(old, nodes)
    write_graph(new, nodes)

    report = diff_graphs(load_graph(old), load_graph(new), set(), "PATCH", 10, 10)

    assert report["classification"] == "PATCH_SAFE"
    assert report["summary"]["removed_public_symbols"] == 0


def test_patch_with_consumer_impacted_removal_is_likely_breaking(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    write_graph(old, [symbol("parse"), symbol("format")])
    write_graph(new, [symbol("format")])

    report = diff_graphs(load_graph(old), load_graph(new), {"parse"}, "PATCH", 10, 10)

    assert report["classification"] == "LIKELY_BREAKING"
    assert report["summary"]["consumer_usage_impacts"] == 1


def test_minor_with_public_removal_is_backpatch_likely(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    write_graph(old, [symbol("legacyApi"), symbol("stableApi")])
    write_graph(new, [symbol("stableApi")])

    report = diff_graphs(load_graph(old), load_graph(new), set(), "MINOR", 10, 10)

    assert report["classification"] == "BACKPATCH_LIKELY"


def test_major_safe_path_is_backpatch_probable(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    write_graph(old, [symbol("stableApi")])
    write_graph(new, [symbol("stableApi")])

    report = diff_graphs(load_graph(old), load_graph(new), set(), "MAJOR", 10, 10)

    assert report["classification"] == "BACKPATCH_PROBABLE"


def test_dead_end_distance_wins(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    write_graph(old, [symbol("stableApi")])
    write_graph(new, [symbol("stableApi")])

    report = diff_graphs(load_graph(old), load_graph(new), set(), "DEAD_END", 10, 10)

    assert report["classification"] == "DEAD_END"


def test_usage_loader_accepts_json_and_text(tmp_path):
    json_usage = tmp_path / "usage.json"
    text_usage = tmp_path / "usage.txt"
    json_usage.write_text(json.dumps({"symbols": ["parse", {"name": "format"}]}))
    text_usage.write_text("# comment\nlegacyApi\n\n")

    assert {"parse", "format"}.issubset(load_usage_labels(json_usage))
    assert load_usage_labels(text_usage) == {"legacyApi"}

import json
from pathlib import Path

from attach_codegenome_analysis import attach


def dataset():
    return {
        "meta": {"external_signals": {}},
        "libraries": [
            {
                "id": "maven|org.example|demo|1.0.0",
                "namespace": "maven",
                "meta": "org.example",
                "proj": "demo",
                "release": "1.0.0",
            }
        ],
    }


def test_attach_matches_by_library_id_and_sets_meta_stats():
    payload = dataset()
    stats = attach(
        payload,
        [
            {
                "analysis_id": "demo-1",
                "library_id": "maven|org.example|demo|1.0.0",
                "classification": "PATCH_SAFE",
                "summary": {"changed_public_symbols": 1},
            }
        ],
    )

    lib = payload["libraries"][0]
    assert stats == {"matched": 1, "unmatched": 0}
    assert lib["codegenome_analyses"][0]["classification"] == "PATCH_SAFE"
    assert lib["codegenome_analyses"][0]["summary"]["changed_public_symbols"] == 1
    assert payload["meta"]["external_signals"]["codegenome_analysis"]["analysis_count"] == 1


def test_attach_matches_by_coordinates_when_library_id_missing():
    payload = dataset()
    stats = attach(
        payload,
        [
            {
                "analysis_id": "demo-2",
                "namespace": "maven",
                "meta": "org.example",
                "proj": "demo",
                "current_release": "1.0.0",
                "classification": "LIKELY_BREAKING",
            }
        ],
    )

    assert stats["matched"] == 1
    assert payload["libraries"][0]["codegenome_analyses"][0]["analysis_id"] == "demo-2"


def test_attach_replaces_existing_analysis_id():
    payload = dataset()
    attach(payload, [{"analysis_id": "demo-1", "library_id": "maven|org.example|demo|1.0.0", "classification": "PATCH_SAFE"}])
    attach(payload, [{"analysis_id": "demo-1", "library_id": "maven|org.example|demo|1.0.0", "classification": "LIKELY_BREAKING"}])

    analyses = payload["libraries"][0]["codegenome_analyses"]
    assert len(analyses) == 1
    assert analyses[0]["classification"] == "LIKELY_BREAKING"


def test_sample_sidecar_shape_is_supported():
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "data" / "codegenome" / "finos-sample-platform.json").read_text(encoding="utf-8"))["analyses"]
    assert rows
    assert all("classification" in row for row in rows)

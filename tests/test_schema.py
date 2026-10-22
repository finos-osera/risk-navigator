from pathlib import Path

from common import canonical_release
from validate_dataset import validate


def test_sample_dataset_schema_validates():
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "finos-sample-platform.json"
    assert dataset_path.exists(), "Run `npm run build:all` before tests"
    errors = validate(dataset_path)
    assert errors == []


def test_sbom_demo_dataset_schema_validates():
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "finos-sbom-demo.json"
    assert dataset_path.exists(), "Run `npm run build:all:finos-sbom-demo` before tests"
    errors = validate(dataset_path)
    assert errors == []


def test_finos_github_org_dataset_schema_validates():
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "finos-github-org.json"
    assert dataset_path.exists(), "Run `npm run build:all:finos-org:full-osv` before tests"
    errors = validate(dataset_path)
    assert errors == []


def test_finos_deep_sbom_demo_dataset_schema_validates():
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "finos-deep-sbom-demo.json"
    assert dataset_path.exists(), "Run `npm run build:all:finos-deep-sbom-demo` before tests"
    errors = validate(dataset_path)
    assert errors == []


def test_version_chains_do_not_duplicate_canonical_releases():
    import json

    data_dir = Path(__file__).resolve().parents[1] / "data"
    for dataset_path in data_dir.glob("*.json"):
        payload = json.loads(dataset_path.read_text())
        for lib in payload.get("libraries", []):
            seen = set()
            namespace = str(lib.get("namespace", ""))
            chain = payload.get("version_chains", {}).get(lib.get("version_chain_ref"), lib.get("version_chain", []))
            for row in chain:
                release = canonical_release(namespace, str(row.get("release", "")))
                assert release not in seen, f"{dataset_path.name} duplicates {lib.get('id')} release {release}"
                seen.add(release)

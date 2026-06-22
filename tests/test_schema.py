from pathlib import Path

from validate_dataset import validate


def test_sample_dataset_schema_validates():
    dataset_path = Path(__file__).resolve().parents[1] / "data" / "finos-sample-platform.json"
    assert dataset_path.exists(), "Run `npm run build:all` before tests"
    errors = validate(dataset_path)
    assert errors == []

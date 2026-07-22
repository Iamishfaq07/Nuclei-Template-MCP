from pathlib import Path

import pytest
import yaml

from mcp_nuclei.core.dedup import find_duplicates


def _write(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data))


def test_find_duplicates_by_id_and_tags(tmp_path: Path):
    _write(
        tmp_path / "existing.yaml",
        {
            "id": "shop-orders-idor",
            "info": {"name": "x", "tags": "idor,bac"},
            "http": [{"matchers": [{"type": "word", "words": ["customer_email"]}]}],
        },
    )

    new_template = {
        "id": "shop-orders-idor-v2",
        "info": {"tags": "idor,bac"},
        "http": [{"matchers": [{"type": "word", "words": ["customer_email"]}]}],
    }

    matches = find_duplicates(new_template, tmp_path)
    assert len(matches) == 1
    assert matches[0].template_id == "shop-orders-idor"
    assert matches[0].score > 0.5


def test_find_duplicates_no_match_below_threshold(tmp_path: Path):
    _write(tmp_path / "unrelated.yaml", {"id": "totally-different", "info": {"tags": "xss"}, "http": []})

    new_template = {"id": "my-sqli-template", "info": {"tags": "sqli"}, "http": []}
    matches = find_duplicates(new_template, tmp_path, threshold=0.3)
    assert matches == []


def test_find_duplicates_recurses_subdirectories(tmp_path: Path):
    sub = tmp_path / "http" / "idor"
    sub.mkdir(parents=True)
    _write(sub / "existing.yaml", {"id": "shop-idor", "info": {"tags": "idor"}, "http": []})

    new_template = {"id": "shop-idor-clone", "info": {"tags": "idor"}, "http": []}
    matches = find_duplicates(new_template, tmp_path)
    assert len(matches) == 1


def test_find_duplicates_skips_invalid_yaml(tmp_path: Path):
    (tmp_path / "broken.yaml").write_text("id: [unterminated")
    new_template = {"id": "x", "info": {}, "http": []}
    assert find_duplicates(new_template, tmp_path) == []


def test_find_duplicates_missing_dir_raises(tmp_path: Path):
    with pytest.raises(NotADirectoryError):
        find_duplicates({"id": "x"}, tmp_path / "nope")


def test_find_duplicates_respects_limit(tmp_path: Path):
    for i in range(5):
        _write(tmp_path / f"t{i}.yaml", {"id": f"shop-idor-{i}", "info": {"tags": "idor"}, "http": []})
    new_template = {"id": "shop-idor-new", "info": {"tags": "idor"}, "http": []}
    matches = find_duplicates(new_template, tmp_path, limit=2)
    assert len(matches) == 2

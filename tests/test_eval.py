from pathlib import Path

import pytest

from mcp_nuclei.core.eval import load_fixture, load_fixtures, run_case, run_eval
from mcp_nuclei.mcp.client import CallableMCPClient

STUB_IDOR = """
id: idor-fixture
info:
  name: IDOR fixture
  tags: idor,bac
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: word
        words: ["leak"]
"""


def _make_fixture(tmp_path: Path, **overrides) -> Path:
    request = tmp_path / "req.req"
    request.write_text("GET /x HTTP/1.1\nHost: t.com\n\n")

    data = {
        "name": "idor-case",
        "request_file": "req.req",
        "description": "IDOR in order endpoint",
        "expected_type": "idor",
        "min_matchers": 1,
        "required_tags": ["idor"],
        **overrides,
    }
    fixture_path = tmp_path / "case.json"
    import json

    fixture_path.write_text(json.dumps(data))
    return fixture_path


def test_load_fixture_resolves_relative_paths(tmp_path: Path):
    fixture_path = _make_fixture(tmp_path)
    case = load_fixture(fixture_path)
    assert case.request_path == (tmp_path / "req.req").resolve()
    assert case.expected_type == "idor"
    assert case.required_tags == ("idor",)


def test_load_fixture_missing_request_file_key_raises(tmp_path: Path):
    fixture_path = tmp_path / "bad.json"
    fixture_path.write_text("{}")
    with pytest.raises(ValueError):
        load_fixture(fixture_path)


def test_load_fixtures_loads_all_json_files(tmp_path: Path):
    _make_fixture(tmp_path)
    cases = load_fixtures(tmp_path)
    assert len(cases) == 1


def test_run_case_passes_when_expectations_met(tmp_path: Path):
    fixture_path = _make_fixture(tmp_path, description="IDOR in order endpoint")
    case = load_fixture(fixture_path)
    client = CallableMCPClient(lambda s, u: STUB_IDOR)

    outcome = run_case(case, client)
    assert outcome.passed is True
    assert outcome.template_id == "idor-fixture"


def test_run_case_fails_on_wrong_type(tmp_path: Path):
    fixture_path = _make_fixture(tmp_path, expected_type="sqli", description="a vague description with no keywords")
    case = load_fixture(fixture_path)
    client = CallableMCPClient(lambda s, u: STUB_IDOR)

    outcome = run_case(case, client)
    assert outcome.passed is False
    assert any("expected detected_type" in r for r in outcome.reasons)


def test_run_case_fails_on_missing_tag(tmp_path: Path):
    fixture_path = _make_fixture(tmp_path, required_tags=["sqli"])
    case = load_fixture(fixture_path)
    client = CallableMCPClient(lambda s, u: STUB_IDOR)

    outcome = run_case(case, client)
    assert outcome.passed is False
    assert any("missing required tag" in r for r in outcome.reasons)


def test_run_case_generation_error_reports_error_not_crash(tmp_path: Path):
    fixture_path = _make_fixture(tmp_path)
    case = load_fixture(fixture_path)
    client = CallableMCPClient(lambda s, u: "")  # empty -> GenerationError

    outcome = run_case(case, client)
    assert outcome.passed is False
    assert outcome.error is not None


def test_run_eval_runs_all_fixtures(tmp_path: Path):
    _make_fixture(tmp_path)
    client = CallableMCPClient(lambda s, u: STUB_IDOR)
    outcomes = run_eval(tmp_path, client)
    assert len(outcomes) == 1
    assert outcomes[0].passed is True

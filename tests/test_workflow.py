from pathlib import Path

import pytest
import yaml

from mcp_nuclei.core.builder import BuildError
from mcp_nuclei.core.parser import ParseError
from mcp_nuclei.core.workflow import build_workflow, to_yaml


def _write_template(path: Path, template_id: str) -> Path:
    path.write_text(yaml.safe_dump({"id": template_id, "info": {"name": "x"}, "http": []}))
    return path


def test_build_workflow_references_paths(tmp_path: Path):
    t1 = _write_template(tmp_path / "a.yaml", "template-a")
    t2 = _write_template(tmp_path / "b.yaml", "template-b")

    wf = build_workflow([t1, t2], workflow_id="My Workflow!", name="My Workflow", author="me")
    assert wf["id"] == "my-workflow"
    assert wf["info"] == {"name": "My Workflow", "author": "me"}
    assert wf["workflows"] == [{"template": str(t1)}, {"template": str(t2)}]


def test_build_workflow_empty_list_raises():
    with pytest.raises(BuildError):
        build_workflow([], workflow_id="x", name="x")


def test_build_workflow_missing_file_raises(tmp_path: Path):
    with pytest.raises(ParseError):
        build_workflow([tmp_path / "missing.yaml"], workflow_id="x", name="x")


def test_build_workflow_non_template_file_raises(tmp_path: Path):
    bad = tmp_path / "notatemplate.yaml"
    bad.write_text(yaml.safe_dump({"foo": "bar"}))
    with pytest.raises(BuildError):
        build_workflow([bad], workflow_id="x", name="x")


def test_to_yaml_roundtrips():
    wf = {"id": "x", "info": {"name": "y"}, "workflows": [{"template": "a.yaml"}]}
    rendered = to_yaml(wf)
    assert yaml.safe_load(rendered) == wf

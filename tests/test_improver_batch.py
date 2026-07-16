from pathlib import Path

import pytest

from mcp_nuclei.core.batch import discover_captures, run_batch
from mcp_nuclei.core.generator import GenerationError
from mcp_nuclei.core.improver import improve_template
from mcp_nuclei.mcp.client import CallableMCPClient

STUB_TEMPLATE = """
id: stub
info:
  name: Stub
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
"""


def test_improve_template(tmp_path: Path):
    template = tmp_path / "t.yaml"
    template.write_text("id: old\ninfo:\n  name: Old\nhttp: []")
    client = CallableMCPClient(lambda s, u: STUB_TEMPLATE)

    result = improve_template(template_path=template, client=client)
    assert result.refined is True
    assert result.template_dict["id"] == "stub"


def test_improve_template_missing_file(tmp_path: Path):
    client = CallableMCPClient(lambda s, u: STUB_TEMPLATE)
    with pytest.raises(GenerationError):
        improve_template(template_path=tmp_path / "nope.yaml", client=client)


def test_discover_captures(tmp_path: Path):
    (tmp_path / "a.req").write_text("GET / HTTP/1.1\nHost: x\n\n")
    (tmp_path / "b.har").write_text("{}")
    (tmp_path / "ignore.md").write_text("nope")
    found = discover_captures(tmp_path)
    names = {p.name for p in found}
    assert names == {"a.req", "b.har"}


def test_run_batch_writes_outputs(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.req").write_text("GET /a HTTP/1.1\nHost: x.com\n\n")
    (src / "b.req").write_text("GET /b HTTP/1.1\nHost: x.com\n\n")
    out = tmp_path / "out"

    client = CallableMCPClient(lambda s, u: STUB_TEMPLATE)
    summary = run_batch(src, client=client, output_dir=out)

    assert summary.succeeded == 2
    assert summary.failed == 0
    assert (out / "a.yaml").exists()
    assert (out / "b.yaml").exists()


def test_run_batch_records_failures(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "good.req").write_text("GET /a HTTP/1.1\nHost: x.com\n\n")

    # Client returns invalid YAML -> generation fails but batch continues.
    client = CallableMCPClient(lambda s, u: "id: [unterminated")
    summary = run_batch(src, client=client, output_dir=tmp_path / "out")
    assert summary.failed == 1
    assert summary.succeeded == 0

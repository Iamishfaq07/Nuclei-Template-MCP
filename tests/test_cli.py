from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_nuclei import cli
from mcp_nuclei.mcp.client import CallableMCPClient, MCPClientError

runner = CliRunner()

STUB_TEMPLATE = """
id: stub-template
info:
  name: Stub Template
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/orders/2001"
    matchers:
      - type: status
        status:
          - 200
"""


@pytest.fixture()
def request_file(tmp_path: Path) -> Path:
    req = tmp_path / "sample.req"
    req.write_text("GET /api/v1/orders/2001 HTTP/1.1\nHost: shop.example.com\n\n")
    return req


def test_version_flag():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "mcp-nuclei" in result.stdout


def test_generate_no_client_configured(request_file: Path, monkeypatch):
    def _raise(backend, model=None):
        raise MCPClientError("no client configured")

    monkeypatch.setattr(cli, "get_client", _raise)
    result = runner.invoke(cli.app, ["generate", "--request", str(request_file)])
    assert result.exit_code == 1
    assert "MCP client error" in result.stderr


def test_generate_writes_output_file(request_file: Path, tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        cli,
        "get_client",
        lambda backend, model=None: CallableMCPClient(lambda system, user: STUB_TEMPLATE),
    )
    output_path = tmp_path / "out.yaml"

    result = runner.invoke(
        cli.app,
        ["generate", "--request", str(request_file), "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "id: stub-template" in output_path.read_text()


def test_generate_missing_request_file():
    result = runner.invoke(cli.app, ["generate", "--request", "/nonexistent/file.req"])
    assert result.exit_code != 0

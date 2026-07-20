from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_nuclei import cli
from mcp_nuclei.core import verify as verify_module
from mcp_nuclei.mcp.client import CallableMCPClient, MCPClientError, Usage

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


class _MeteredStubClient:
    def __init__(self, response: str):
        self._response = response
        self.last_usage = None
        self.calls = 0

    def generate(self, *, system_prompt, user_prompt):
        self.calls += 1
        self.last_usage = Usage(model="claude-sonnet-5", input_tokens=100, output_tokens=50)
        if "rationale" in system_prompt.lower() or "explaining" in system_prompt.lower():
            return "Short rationale."
        return self._response


def test_generate_explain_and_cost(request_file: Path, monkeypatch):
    stub = _MeteredStubClient(STUB_TEMPLATE)
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: stub)

    result = runner.invoke(cli.app, ["generate", "--request", str(request_file), "--explain", "--cost"])
    assert result.exit_code == 0
    assert "Why this template" in result.stdout
    assert "Short rationale." in result.stdout
    assert "MCP call(s)" in result.stdout


def test_generate_cache_avoids_second_call(request_file: Path, tmp_path: Path, monkeypatch):
    import mcp_nuclei.mcp.cache as cache_module

    monkeypatch.setattr(cache_module, "default_cache_dir", lambda: tmp_path / "cache")
    stub = _MeteredStubClient(STUB_TEMPLATE)
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: stub)

    runner.invoke(cli.app, ["generate", "--request", str(request_file), "--cache"])
    calls_after_first = stub.calls
    runner.invoke(cli.app, ["generate", "--request", str(request_file), "--cache"])
    assert stub.calls == calls_after_first  # second run served from cache


def test_generate_verify_url_unavailable_is_non_fatal(request_file: Path, monkeypatch):
    monkeypatch.setattr(
        cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE)
    )
    monkeypatch.setattr(verify_module, "nuclei_path", lambda: None)

    result = runner.invoke(
        cli.app, ["generate", "--request", str(request_file), "--verify-url", "http://example.invalid"]
    )
    assert result.exit_code == 0
    assert "Live verification skipped" in result.stdout


def test_improve_diff_shows_panel(tmp_path: Path, monkeypatch):
    template = tmp_path / "old.yaml"
    template.write_text("id: old\ninfo:\n  name: Old\nhttp: []\n")
    monkeypatch.setattr(
        cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE)
    )

    result = runner.invoke(cli.app, ["improve", "--template", str(template), "--diff"])
    assert result.exit_code == 0
    assert "diff" in result.stdout.lower()

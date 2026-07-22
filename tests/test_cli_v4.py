import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from mcp_nuclei import cli
from mcp_nuclei.mcp.client import CallableMCPClient

runner = CliRunner()

STUB_TEMPLATE = """
id: stub-template
info:
  name: Stub Template
  severity: high
  tags: idor
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


@pytest.fixture()
def template_file(tmp_path: Path) -> Path:
    path = tmp_path / "template.yaml"
    path.write_text(STUB_TEMPLATE)
    return path


def _isolate_history(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("mcp_nuclei.core.history.default_history_path", lambda: tmp_path / "history.db")


# --------------------------------------------------------------------------- #
# lint
# --------------------------------------------------------------------------- #


def test_lint_command_clean_template(template_file: Path):
    result = runner.invoke(cli.app, ["lint", "--template", str(template_file)])
    assert result.exit_code == 0


def test_lint_command_errors_on_missing_name(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"id": "x", "info": {}, "http": []}))
    result = runner.invoke(cli.app, ["lint", "--template", str(bad)])
    assert result.exit_code == 1


def test_lint_command_invalid_yaml(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: [unterminated")
    result = runner.invoke(cli.app, ["lint", "--template", str(bad)])
    assert result.exit_code == 1


# --------------------------------------------------------------------------- #
# workflow
# --------------------------------------------------------------------------- #


def test_workflow_command_writes_output(template_file: Path, tmp_path: Path):
    out = tmp_path / "wf.yaml"
    result = runner.invoke(
        cli.app,
        ["workflow", "--template", str(template_file), "--id", "wf", "--name", "WF", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    data = yaml.safe_load(out.read_text())
    assert data["id"] == "wf"


def test_workflow_command_missing_template_fails(tmp_path: Path):
    result = runner.invoke(cli.app, ["workflow", "--template", str(tmp_path / "nope.yaml"), "--id", "wf", "--name", "WF"])
    assert result.exit_code != 0


# --------------------------------------------------------------------------- #
# dedup
# --------------------------------------------------------------------------- #


def test_dedup_command_reports_matches(template_file: Path, tmp_path: Path):
    existing_dir = tmp_path / "existing"
    existing_dir.mkdir()
    (existing_dir / "same.yaml").write_text(STUB_TEMPLATE)

    result = runner.invoke(cli.app, ["dedup", "--template", str(template_file), "--against", str(existing_dir)])
    assert result.exit_code == 0
    assert "stub-template" in result.stdout


def test_dedup_command_no_matches(template_file: Path, tmp_path: Path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    result = runner.invoke(cli.app, ["dedup", "--template", str(template_file), "--against", str(empty_dir)])
    assert result.exit_code == 0
    assert "No likely duplicates" in result.stdout


# --------------------------------------------------------------------------- #
# eval
# --------------------------------------------------------------------------- #


def test_eval_command_reports_pass(tmp_path: Path, monkeypatch):
    req = tmp_path / "req.req"
    req.write_text("GET /x HTTP/1.1\nHost: t.com\n\n")
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()
    (fixtures_dir / "case.json").write_text(
        json.dumps(
            {
                "name": "case",
                "request_file": "../req.req",
                "description": "IDOR in order endpoint",
                "expected_type": "idor",
                "required_tags": ["idor"],
            }
        )
    )

    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))
    result = runner.invoke(cli.app, ["eval", "--fixtures", str(fixtures_dir)])
    assert result.exit_code == 0
    assert "1/1 passed" in result.stdout


# --------------------------------------------------------------------------- #
# history
# --------------------------------------------------------------------------- #


def test_history_command_empty(tmp_path: Path, monkeypatch):
    _isolate_history(monkeypatch, tmp_path)
    result = runner.invoke(cli.app, ["history"])
    assert result.exit_code == 0
    assert "No history recorded" in result.stdout


def test_generate_history_flag_records_run(request_file: Path, tmp_path: Path, monkeypatch):
    _isolate_history(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))

    result = runner.invoke(cli.app, ["generate", "--request", str(request_file), "--history"])
    assert result.exit_code == 0

    history_result = runner.invoke(cli.app, ["history"])
    assert "stub-template" in history_result.stdout


def test_generate_without_history_flag_does_not_record(request_file: Path, tmp_path: Path, monkeypatch):
    _isolate_history(monkeypatch, tmp_path)
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))

    runner.invoke(cli.app, ["generate", "--request", str(request_file)])
    history_result = runner.invoke(cli.app, ["history"])
    assert "No history recorded" in history_result.stdout


# --------------------------------------------------------------------------- #
# generate: --retries, --cve-id/--cwe-id, --verify-safe-url, --verify-urls-file, --notify-webhook
# --------------------------------------------------------------------------- #


def test_generate_retries_recovers_from_transient_failure(request_file: Path, monkeypatch):
    class _Flaky:
        def __init__(self):
            self.n = 0

        def generate(self, *, system_prompt, user_prompt):
            self.n += 1
            if self.n < 2:
                raise RuntimeError("transient")
            return STUB_TEMPLATE

    flaky = _Flaky()
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: flaky)
    monkeypatch.setattr("mcp_nuclei.mcp.retry.time.sleep", lambda _: None)

    result = runner.invoke(cli.app, ["generate", "--request", str(request_file), "--retries", "2"])
    assert result.exit_code == 0
    assert flaky.n == 2


def test_generate_cve_cwe_embedded_in_classification(request_file: Path, monkeypatch):
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))

    result = runner.invoke(
        cli.app,
        ["generate", "--request", str(request_file), "--cve-id", "CVE-2024-99999", "--cwe-id", "CWE-200", "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "cve-2024-99999" in payload["template"].lower()


def test_generate_verify_safe_url_skips_gracefully_without_nuclei(request_file: Path, monkeypatch):
    from mcp_nuclei.core import verify as verify_module

    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))
    monkeypatch.setattr(verify_module, "nuclei_path", lambda: None)

    result = runner.invoke(
        cli.app, ["generate", "--request", str(request_file), "--verify-safe-url", "http://patched.invalid"]
    )
    assert result.exit_code == 0
    assert "Live verification skipped" in result.stdout


def test_generate_verify_urls_file(request_file: Path, tmp_path: Path, monkeypatch):
    from mcp_nuclei.core import verify as verify_module

    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))

    def fake_verify_yaml(template_yaml, url, extra_args=None, timeout=30):
        return verify_module.VerifyResult(ran=True, matched=(url == "http://a.invalid"), available=True)

    # verify_targets() (used for --verify-urls-file) calls verify_yaml via its own
    # module's global namespace, so the module-level function must be patched.
    monkeypatch.setattr(verify_module, "verify_yaml", fake_verify_yaml)

    targets = tmp_path / "targets.txt"
    targets.write_text("http://a.invalid\nhttp://b.invalid\n")

    result = runner.invoke(
        cli.app, ["generate", "--request", str(request_file), "--verify-urls-file", str(targets)]
    )
    assert result.exit_code == 0
    assert "1/2 target(s) matched" in result.stdout


def test_generate_notify_webhook_failure_is_non_fatal(request_file: Path, monkeypatch):
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))

    def fake_notify(url, text, extra=None):
        from mcp_nuclei.core.notify import NotifyResult

        return NotifyResult(sent=False, error="connection refused")

    monkeypatch.setattr(cli, "notify_webhook", fake_notify)

    result = runner.invoke(
        cli.app, ["generate", "--request", str(request_file), "--notify-webhook", "http://hooks.invalid/x"]
    )
    assert result.exit_code == 0  # notification failure must not fail the command
    assert "Webhook notification failed" in result.stderr


# --------------------------------------------------------------------------- #
# batch: --workers, --history
# --------------------------------------------------------------------------- #


def test_batch_workers_flag_accepted(tmp_path: Path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.req").write_text("GET /a HTTP/1.1\nHost: t.com\n\n")
    (src / "b.req").write_text("GET /b HTTP/1.1\nHost: t.com\n\n")

    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))
    result = runner.invoke(
        cli.app, ["batch", "--dir", str(src), "--output-dir", str(tmp_path / "out"), "--workers", "2"]
    )
    assert result.exit_code == 0
    assert "2 succeeded" in result.stdout


def test_batch_history_flag_records_each_item(tmp_path: Path, monkeypatch):
    _isolate_history(monkeypatch, tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.req").write_text("GET /a HTTP/1.1\nHost: t.com\n\n")

    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: CallableMCPClient(lambda s, u: STUB_TEMPLATE))
    runner.invoke(cli.app, ["batch", "--dir", str(src), "--output-dir", str(tmp_path / "out"), "--history"])

    history_result = runner.invoke(cli.app, ["history"])
    assert "stub-template" in history_result.stdout


# --------------------------------------------------------------------------- #
# improve: --verify-safe-url, --retries
# --------------------------------------------------------------------------- #


def test_improve_retries_flag(template_file: Path, monkeypatch):
    class _Flaky:
        def __init__(self):
            self.n = 0

        def generate(self, *, system_prompt, user_prompt):
            self.n += 1
            if self.n < 2:
                raise RuntimeError("transient")
            return STUB_TEMPLATE

    flaky = _Flaky()
    monkeypatch.setattr(cli, "get_client", lambda backend, model=None: flaky)
    monkeypatch.setattr("mcp_nuclei.mcp.retry.time.sleep", lambda _: None)

    result = runner.invoke(cli.app, ["improve", "--template", str(template_file), "--retries", "2"])
    assert result.exit_code == 0
    assert flaky.n == 2

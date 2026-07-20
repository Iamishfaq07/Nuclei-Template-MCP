import json

from mcp_nuclei.core import verify


def test_verify_yaml_reports_unavailable(monkeypatch):
    monkeypatch.setattr(verify, "nuclei_path", lambda: None)
    result = verify.verify_yaml("id: x\ninfo: {}\nhttp: []", "http://example.invalid")
    assert result.available is False
    assert result.ran is False
    assert result.matched is False
    assert "nuclei" in result.detail.lower()


def test_verify_yaml_reports_match(monkeypatch):
    match_line = json.dumps({"template-id": "x", "matched-at": "http://t/x"})

    class _Proc:
        stdout = match_line + "\n"
        stderr = ""

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **k: _Proc())

    result = verify.verify_yaml("id: x\ninfo: {}\nhttp: []", "http://example.invalid")
    assert result.ran is True
    assert result.available is True
    assert result.matched is True
    assert len(result.matches) == 1
    assert result.matches[0]["template-id"] == "x"


def test_verify_yaml_reports_no_match(monkeypatch):
    class _Proc:
        stdout = ""
        stderr = ""

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **k: _Proc())

    result = verify.verify_yaml("id: x\ninfo: {}\nhttp: []", "http://example.invalid")
    assert result.matched is False
    assert result.ran is True


def test_verify_yaml_ignores_malformed_json_lines(monkeypatch):
    class _Proc:
        stdout = "not json\n" + json.dumps({"template-id": "x"}) + "\n"
        stderr = ""

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", lambda *a, **k: _Proc())

    result = verify.verify_yaml("id: x", "http://example.invalid")
    assert len(result.matches) == 1


def test_verify_yaml_handles_timeout(monkeypatch):
    import subprocess

    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nuclei", timeout=1)

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", _raise)

    result = verify.verify_yaml("id: x", "http://example.invalid", timeout=1)
    assert result.ran is True
    assert result.matched is False
    assert "timed out" in result.detail

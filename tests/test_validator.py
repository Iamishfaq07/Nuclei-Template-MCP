from mcp_nuclei.core import validator


def test_validate_yaml_reports_unavailable(monkeypatch):
    monkeypatch.setattr(validator, "nuclei_path", lambda: None)
    result = validator.validate_yaml("id: x\ninfo: {}\nhttp: []")
    assert result.available is False
    assert result.ok is False
    assert "nuclei" in result.detail.lower()


def test_validate_file_runs_binary(monkeypatch, tmp_path):
    class _Proc:
        returncode = 0
        stdout = "template validated"
        stderr = ""

    monkeypatch.setattr(validator, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(validator.subprocess, "run", lambda *a, **k: _Proc())

    template = tmp_path / "t.yaml"
    template.write_text("id: x")
    result = validator.validate_file(template)
    assert result.available is True
    assert result.ok is True
    assert "validated" in result.output


def test_validate_file_reports_failure(monkeypatch, tmp_path):
    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "invalid template"

    monkeypatch.setattr(validator, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(validator.subprocess, "run", lambda *a, **k: _Proc())

    template = tmp_path / "t.yaml"
    template.write_text("bad")
    result = validator.validate_file(template)
    assert result.ok is False
    assert "invalid template" in result.output

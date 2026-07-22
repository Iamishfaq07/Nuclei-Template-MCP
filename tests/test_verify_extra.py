import json

from mcp_nuclei.core import verify


def test_verify_targets_runs_each_url(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        class _Proc:
            stdout = ""
            stderr = ""

        return _Proc()

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", fake_run)

    results = verify.verify_targets("id: x", ["http://a.invalid", "http://b.invalid"])
    assert set(results.keys()) == {"http://a.invalid", "http://b.invalid"}
    assert len(calls) == 2
    assert all(r.ran for r in results.values())


def test_verify_targets_reports_per_url_match(monkeypatch):
    def fake_run(cmd, **kwargs):
        url = cmd[cmd.index("-u") + 1]

        class _Proc:
            stdout = (json.dumps({"template-id": "x"}) + "\n") if url == "http://vuln.invalid" else ""
            stderr = ""

        return _Proc()

    monkeypatch.setattr(verify, "nuclei_path", lambda: "/usr/bin/nuclei")
    monkeypatch.setattr(verify.subprocess, "run", fake_run)

    results = verify.verify_targets("id: x", ["http://vuln.invalid", "http://safe.invalid"])
    assert results["http://vuln.invalid"].matched is True
    assert results["http://safe.invalid"].matched is False


def test_read_targets_file_skips_blank_and_comment_lines(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("http://a.invalid\n\n# a comment\nhttp://b.invalid\n   \n")
    assert verify.read_targets_file(targets) == ["http://a.invalid", "http://b.invalid"]

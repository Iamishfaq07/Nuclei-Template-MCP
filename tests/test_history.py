from pathlib import Path

from mcp_nuclei.core.history import RunRecord, default_history_path, list_runs, record_run


def test_record_and_list_runs(tmp_path: Path):
    db = tmp_path / "history.db"
    record_run(RunRecord(command="generate", template_id="foo", detected_type="idor"), path=db)
    record_run(RunRecord(command="improve", template_id="bar"), path=db)

    records = list_runs(path=db)
    assert len(records) == 2
    assert records[0].command == "improve"  # most recent first
    assert records[1].template_id == "foo"


def test_list_runs_respects_limit(tmp_path: Path):
    db = tmp_path / "history.db"
    for i in range(5):
        record_run(RunRecord(command="generate", template_id=f"t{i}"), path=db)
    assert len(list_runs(limit=2, path=db)) == 2


def test_list_runs_missing_db_returns_empty(tmp_path: Path):
    assert list_runs(path=tmp_path / "nonexistent.db") == []


def test_record_run_survives_unwritable_path(tmp_path: Path):
    # Parent is actually a file, not a directory -> mkdir will fail; must not raise.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    bad_path = blocker / "sub" / "history.db"
    record_run(RunRecord(command="generate"), path=bad_path)  # should not raise


def test_default_history_path_uses_xdg(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert default_history_path() == tmp_path / "mcp-nuclei" / "history.db"

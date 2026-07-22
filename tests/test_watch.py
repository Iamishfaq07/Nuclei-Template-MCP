from pathlib import Path

from mcp_nuclei.core.watch import scan_for_changes, watch_directory
from mcp_nuclei.mcp.client import CallableMCPClient

STUB = "id: w\ninfo:\n  name: W\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n"


def test_scan_for_changes_lists_capture_files(tmp_path: Path):
    (tmp_path / "a.req").write_text("x")
    (tmp_path / "notes.md").write_text("ignore me")
    found = scan_for_changes(tmp_path)
    assert [p.name for p in found] == ["a.req"]


def test_watch_directory_ignores_pre_existing_files(tmp_path: Path):
    (tmp_path / "old.req").write_text("GET /old HTTP/1.1\nHost: t.com\n\n")
    client = CallableMCPClient(lambda s, u: STUB)

    items = list(
        watch_directory(tmp_path, client=client, poll_interval=0.01, max_iterations=1, sleep_fn=lambda _: None)
    )
    assert items == []


def test_watch_directory_process_existing_true(tmp_path: Path):
    (tmp_path / "old.req").write_text("GET /old HTTP/1.1\nHost: t.com\n\n")
    client = CallableMCPClient(lambda s, u: STUB)

    items = list(
        watch_directory(
            tmp_path, client=client, poll_interval=0.01, max_iterations=1,
            sleep_fn=lambda _: None, process_existing=True,
        )
    )
    assert len(items) == 1
    assert items[0].ok


def test_watch_directory_detects_new_file_between_scans(tmp_path: Path):
    client = CallableMCPClient(lambda s, u: STUB)

    def sleep_and_add(_secs):
        (tmp_path / "new.req").write_text("GET /new HTTP/1.1\nHost: t.com\n\n")

    items = list(
        watch_directory(tmp_path, client=client, poll_interval=0.01, max_iterations=2, sleep_fn=sleep_and_add)
    )
    assert len(items) == 1
    assert items[0].label == "new.req"


def test_watch_directory_writes_output(tmp_path: Path):
    (tmp_path / "captures").mkdir()
    captures_dir = tmp_path / "captures"
    out_dir = tmp_path / "out"
    client = CallableMCPClient(lambda s, u: STUB)

    def sleep_and_add(_secs):
        (captures_dir / "x.req").write_text("GET /x HTTP/1.1\nHost: t.com\n\n")

    items = list(
        watch_directory(
            captures_dir, client=client, output_dir=out_dir, poll_interval=0.01,
            max_iterations=2, sleep_fn=sleep_and_add,
        )
    )
    assert len(items) == 1
    assert items[0].output_path is not None
    assert items[0].output_path.exists()

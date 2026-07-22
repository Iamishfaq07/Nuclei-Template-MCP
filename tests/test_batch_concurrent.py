import threading
import time
from pathlib import Path

from mcp_nuclei.core.batch import run_batch

STUB = "id: t\ninfo:\n  name: T\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/x\"]\n"


class _SlowConcurrentClient:
    """Records concurrent call overlap to prove requests actually run in parallel."""

    def __init__(self, delay: float = 0.05):
        self._delay = delay
        self.max_concurrent = 0
        self._current = 0
        self._lock = threading.Lock()

    def generate(self, *, system_prompt, user_prompt):
        with self._lock:
            self._current += 1
            self.max_concurrent = max(self.max_concurrent, self._current)
        time.sleep(self._delay)
        with self._lock:
            self._current -= 1
        return STUB


def test_run_batch_sequential_by_default(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(3):
        (src / f"{i}.req").write_text(f"GET /{i} HTTP/1.1\nHost: t.com\n\n")

    client = _SlowConcurrentClient()
    summary = run_batch(src, client=client, output_dir=tmp_path / "out")
    assert summary.succeeded == 3
    assert client.max_concurrent == 1


def test_run_batch_concurrent_with_workers(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(4):
        (src / f"{i}.req").write_text(f"GET /{i} HTTP/1.1\nHost: t.com\n\n")

    client = _SlowConcurrentClient()
    summary = run_batch(src, client=client, output_dir=tmp_path / "out", max_workers=4)
    assert summary.succeeded == 4
    assert client.max_concurrent > 1


def test_run_batch_concurrent_preserves_discovery_order(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(5):
        (src / f"{i}.req").write_text(f"GET /{i} HTTP/1.1\nHost: t.com\n\n")

    client = _SlowConcurrentClient(delay=0.01)
    summary = run_batch(src, client=client, max_workers=3)
    labels = [item.source.name for item in summary.items]
    assert labels == sorted(labels)

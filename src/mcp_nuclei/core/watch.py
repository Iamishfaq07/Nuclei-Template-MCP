"""Watch mode: auto-generate templates as new captures land in a directory.

Backs the `watch` command, for a live triage workflow where an analyst
drops a `.req`/`.har`/etc. file into a directory (e.g. exported straight
from Burp) and gets a generated template back without re-running the CLI
by hand each time.

Implemented as simple mtime-based polling rather than a filesystem-events
library (inotify/watchdog) to avoid adding a new dependency — capture
files are small and infrequent, so a short poll interval is more than
responsive enough.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mcp_nuclei.core.batch import CAPTURE_SUFFIXES, BatchItem, _process_source
from mcp_nuclei.core.generator import GenerationError
from mcp_nuclei.mcp.client import MCPClient


@dataclass
class WatchState:
    """Tracks the last-seen modification time of each capture file."""

    seen_mtimes: dict[Path, float] = field(default_factory=dict)


def scan_for_changes(directory: Path) -> list[Path]:
    """List capture files currently present in `directory`."""
    if not directory.exists() or not directory.is_dir():
        raise GenerationError(f"Not a directory: {directory}")
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES)


def _diff_and_update(directory: Path, state: WatchState) -> list[Path]:
    """Return capture files that are new or modified since the last scan."""
    changed = []
    for path in scan_for_changes(directory):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if state.seen_mtimes.get(path) != mtime:
            changed.append(path)
        state.seen_mtimes[path] = mtime
    return changed


def watch_directory(
    directory: Path,
    *,
    client: MCPClient,
    output_dir: Optional[Path] = None,
    fmt: str = "auto",
    author: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    auto_classify: bool = False,
    refine: bool = False,
    poll_interval: float = 2.0,
    max_iterations: Optional[int] = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    process_existing: bool = False,
) -> Iterator[BatchItem]:
    """Poll `directory` and yield a `BatchItem` for each new/changed capture.

    Runs forever (`max_iterations=None`) unless the caller breaks out of
    the iteration (e.g. on `KeyboardInterrupt`) or passes a finite
    `max_iterations` — used by tests to avoid an infinite loop.
    Files already present when watching starts are ignored unless
    `process_existing=True`.
    """
    state = WatchState()
    if not process_existing:
        for path in scan_for_changes(directory):
            try:
                state.seen_mtimes[path] = path.stat().st_mtime
            except OSError:
                continue

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        for source in _diff_and_update(directory, state):
            yield from _process_source(
                source,
                client=client,
                output_dir=output_dir,
                fmt=fmt,
                author=author,
                severity=severity,
                tags=tags,
                auto_classify=auto_classify,
                refine=refine,
            )
        iterations += 1
        if max_iterations is None or iterations < max_iterations:
            sleep_fn(poll_interval)

"""Local run history: a lightweight audit trail for `generate`/`improve`/`batch` runs.

Stores one row per run in a local SQLite database — enough for cost
accounting and "what did I generate last week" lookups. Deliberately does
NOT store the raw request/response/prompt content (which may contain
sensitive target details, tokens, or PII): only metadata about the run
itself. The database never leaves the local machine.
"""
from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    command TEXT NOT NULL,
    template_id TEXT,
    detected_type TEXT,
    source_label TEXT,
    backend TEXT,
    model TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    estimated_cost_usd REAL
)
"""


@dataclass
class RunRecord:
    """One logged run."""

    command: str
    template_id: Optional[str] = None
    detected_type: Optional[str] = None
    source_label: Optional[str] = None
    backend: Optional[str] = None
    model: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    estimated_cost_usd: Optional[float] = None
    timestamp: float = 0.0


def default_history_path() -> Path:
    """Return the default history database path, honoring XDG_DATA_HOME."""
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "mcp-nuclei" / "history.db"


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    return conn


def record_run(record: RunRecord, path: Optional[Path] = None) -> None:
    """Append a run to the history database. Best-effort: failures are swallowed.

    History is a convenience log, not a critical path — a write failure
    (e.g. read-only filesystem, disk full) must never break a CLI command.
    """
    db_path = path or default_history_path()
    timestamp = record.timestamp or time.time()
    try:
        with _connect(db_path) as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    timestamp, command, template_id, detected_type, source_label,
                    backend, model, input_tokens, output_tokens, estimated_cost_usd
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    record.command,
                    record.template_id,
                    record.detected_type,
                    record.source_label,
                    record.backend,
                    record.model,
                    record.input_tokens,
                    record.output_tokens,
                    record.estimated_cost_usd,
                ),
            )
    except (sqlite3.Error, OSError):
        pass


def list_runs(limit: int = 20, path: Optional[Path] = None) -> list[RunRecord]:
    """Return the most recent runs, newest first."""
    db_path = path or default_history_path()
    if not db_path.exists():
        return []
    try:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT timestamp, command, template_id, detected_type, source_label,
                       backend, model, input_tokens, output_tokens, estimated_cost_usd
                FROM runs ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    except sqlite3.Error:
        return []

    return [
        RunRecord(
            timestamp=row[0],
            command=row[1],
            template_id=row[2],
            detected_type=row[3],
            source_label=row[4],
            backend=row[5],
            model=row[6],
            input_tokens=row[7],
            output_tokens=row[8],
            estimated_cost_usd=row[9],
        )
        for row in rows
    ]

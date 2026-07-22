"""Batch generation: turn a directory of captures into many templates.

Backs the `batch` command. It walks a directory for capture files
(`.req`, `.txt`, `.curl`, `.har`, `.xml`), generates a template for each
request found, and reports per-file success/failure without aborting the
whole run on a single bad input. With `max_workers > 1`, captures are
processed concurrently via a thread pool — the underlying HTTP clients
used by the Anthropic/OpenAI SDKs are safe to share across threads, and
each call is otherwise independent.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mcp_nuclei.core.generator import (
    GenerationError,
    GenerationResult,
    generate_from_capture,
    load_captures,
)
from mcp_nuclei.mcp.client import MCPClient

# File extensions we treat as importable captures in batch mode.
CAPTURE_SUFFIXES = {".req", ".txt", ".http", ".curl", ".har", ".xml", ".json", ".yaml", ".yml"}


@dataclass
class BatchItem:
    """Result of processing one capture within a batch run."""

    source: Path
    label: Optional[str]
    result: Optional[GenerationResult] = None
    error: Optional[str] = None
    output_path: Optional[Path] = None

    @property
    def ok(self) -> bool:
        return self.result is not None and self.error is None


@dataclass
class BatchSummary:
    """Aggregate outcome of a batch run."""

    items: list[BatchItem] = field(default_factory=list)

    @property
    def succeeded(self) -> int:
        return sum(1 for item in self.items if item.ok)

    @property
    def failed(self) -> int:
        return sum(1 for item in self.items if not item.ok)


def discover_captures(directory: Path) -> list[Path]:
    """Find candidate capture files in a directory (non-recursive by default)."""
    if not directory.exists() or not directory.is_dir():
        raise GenerationError(f"Not a directory: {directory}")
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in CAPTURE_SUFFIXES)


def _process_source(
    source: Path,
    *,
    client: MCPClient,
    output_dir: Optional[Path],
    fmt: str,
    author: Optional[str],
    severity: Optional[str],
    tags: Optional[str],
    auto_classify: bool,
    refine: bool,
) -> list[BatchItem]:
    """Generate templates for every capture found in a single source file."""
    try:
        captures = load_captures(source, fmt=fmt)
    except GenerationError as exc:
        return [BatchItem(source=source, label=source.name, error=str(exc))]

    items: list[BatchItem] = []
    for index, capture in enumerate(captures):
        item = BatchItem(source=source, label=capture.label or source.name)
        try:
            result = generate_from_capture(
                capture,
                client=client,
                author=author,
                severity=severity,
                tags=tags,
                auto_classify=auto_classify,
                refine=refine,
            )
            item.result = result
            if output_dir is not None:
                stem = source.stem if len(captures) == 1 else f"{source.stem}-{index}"
                out_path = output_dir / f"{stem}.yaml"
                out_path.write_text(result.template_yaml, encoding="utf-8")
                item.output_path = out_path
        except GenerationError as exc:
            item.error = str(exc)
        items.append(item)
    return items


def run_batch(
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
    max_workers: int = 1,
) -> BatchSummary:
    """Generate templates for every capture found in `directory`.

    `max_workers` controls concurrency: 1 (default) processes sources
    sequentially in discovery order; >1 processes them concurrently via a
    thread pool, while still returning results in discovery order.
    """
    summary = BatchSummary()
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)

    sources = discover_captures(directory)

    def _run(source: Path) -> list[BatchItem]:
        return _process_source(
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

    if max_workers <= 1 or len(sources) <= 1:
        for source in sources:
            summary.items.extend(_run(source))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for items in executor.map(_run, sources):
                summary.items.extend(items)

    return summary

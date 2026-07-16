"""Batch generation: turn a directory of captures into many templates.

Backs the `batch` command. It walks a directory for capture files
(`.req`, `.txt`, `.curl`, `.har`, `.xml`), generates a template for each
request found, and reports per-file success/failure without aborting the
whole run on a single bad input.
"""
from __future__ import annotations

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
CAPTURE_SUFFIXES = {".req", ".txt", ".http", ".curl", ".har", ".xml"}


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
) -> BatchSummary:
    """Generate templates for every capture found in `directory`."""
    summary = BatchSummary()
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)

    for source in discover_captures(directory):
        try:
            captures = load_captures(source, fmt=fmt)
        except GenerationError as exc:
            summary.items.append(BatchItem(source=source, label=source.name, error=str(exc)))
            continue

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
            summary.items.append(item)

    return summary

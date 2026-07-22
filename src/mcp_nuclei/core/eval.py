"""Prompt regression harness.

Replays a small set of fixture requests through the real generation
pipeline (using whatever backend the caller configures) and checks
structural expectations on the result: the detected vuln type, a minimum
matcher count, and required tags. This is a developer tool for guarding
against prompt regressions when editing `prompts/*.txt` — it needs a live
MCP backend to run, since it exercises real generation, not a mock.

Fixtures are JSON files shaped like:

    {
      "name": "idor-order-endpoint",
      "request_file": "../requests/idor-order-endpoint.req",
      "response_file": "../requests/idor-order-endpoint.resp",
      "description": "IDOR in order endpoint",
      "expected_type": "idor",
      "min_matchers": 1,
      "required_tags": ["idor"]
    }

`request_file`/`response_file` are resolved relative to the fixture file's
own directory.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mcp_nuclei.core.generator import GenerationError, generate_template
from mcp_nuclei.mcp.client import MCPClient


@dataclass
class EvalCase:
    """A single fixture to replay through generation."""

    name: str
    request_path: Path
    response_path: Optional[Path] = None
    description: Optional[str] = None
    expected_type: Optional[str] = None
    min_matchers: int = 1
    required_tags: tuple[str, ...] = ()


@dataclass
class EvalOutcome:
    """Result of running one `EvalCase`."""

    case: EvalCase
    passed: bool
    reasons: list[str] = field(default_factory=list)
    detected_type: Optional[str] = None
    template_id: Optional[str] = None
    error: Optional[str] = None


def load_fixture(path: Path) -> EvalCase:
    """Load a single fixture JSON file into an `EvalCase`."""
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    base = path.parent

    request_file = data.get("request_file")
    if not request_file:
        raise ValueError(f"Fixture {path} is missing 'request_file'")

    response_file = data.get("response_file")
    return EvalCase(
        name=data.get("name", path.stem),
        request_path=(base / request_file).resolve(),
        response_path=(base / response_file).resolve() if response_file else None,
        description=data.get("description"),
        expected_type=data.get("expected_type"),
        min_matchers=int(data.get("min_matchers", 1)),
        required_tags=tuple(data.get("required_tags", [])),
    )


def load_fixtures(directory: Path) -> list[EvalCase]:
    """Load every `*.json` fixture in `directory`, sorted by filename."""
    if not directory.exists() or not directory.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")
    return [load_fixture(p) for p in sorted(directory.glob("*.json"))]


def _count_matchers(template: dict[str, Any]) -> int:
    count = 0
    for block_key in ("http", "network", "dns", "file", "headless", "ssl", "websocket"):
        for block in template.get(block_key) or []:
            if isinstance(block, dict):
                count += len(block.get("matchers") or [])
    return count


def run_case(case: EvalCase, client: MCPClient) -> EvalOutcome:
    """Run generation for one fixture and check it against expectations."""
    try:
        result = generate_template(
            request_path=case.request_path,
            client=client,
            response_path=case.response_path,
            description=case.description,
        )
    except GenerationError as exc:
        return EvalOutcome(case=case, passed=False, error=str(exc))

    reasons: list[str] = []
    if case.expected_type and result.detected_type != case.expected_type:
        reasons.append(f"expected detected_type={case.expected_type!r}, got {result.detected_type!r}")

    matcher_count = _count_matchers(result.template_dict)
    if matcher_count < case.min_matchers:
        reasons.append(f"expected >= {case.min_matchers} matcher(s), found {matcher_count}")

    tags = {t.strip() for t in str((result.template_dict.get("info") or {}).get("tags", "")).split(",")}
    missing = [t for t in case.required_tags if t not in tags]
    if missing:
        reasons.append(f"missing required tag(s): {missing}")

    return EvalOutcome(
        case=case,
        passed=not reasons,
        reasons=reasons,
        detected_type=result.detected_type,
        template_id=result.template_dict.get("id"),
    )


def run_eval(fixtures_dir: Path, client: MCPClient) -> list[EvalOutcome]:
    """Run every fixture in `fixtures_dir` and return their outcomes."""
    return [run_case(case, client) for case in load_fixtures(fixtures_dir)]

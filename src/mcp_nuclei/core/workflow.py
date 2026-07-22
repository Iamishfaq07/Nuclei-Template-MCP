"""Combine several existing templates into a Nuclei workflow file.

A Nuclei "workflow" is a small YAML file that chains multiple templates
together (e.g. run a technology-detection template first, and only run
the exploit template if it matches). Nuclei resolves each `workflows[].
template` entry as a file path (relative to wherever `-w`/`-t` point at
runtime), not a template id — so this validates each input file looks
like a real template, then references it by path. This is pure mechanical
YAML construction; no MCP call is needed since the inputs are templates
the caller already has and chose.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_nuclei.core.builder import BuildError, slugify_id
from mcp_nuclei.core.parser import ParseError


def _validate_template_file(path: Path) -> None:
    if not path.exists():
        raise ParseError(f"Template file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise BuildError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or not data.get("id"):
        raise BuildError(f"{path} has no top-level 'id' field; it doesn't look like a Nuclei template")


def build_workflow(
    template_paths: list[Path],
    *,
    workflow_id: str,
    name: str,
    author: str = "mcp-nuclei",
) -> dict[str, Any]:
    """Build a workflow dict chaining each template, in the order given.

    Each entry's `template:` value is the path as passed in (validated to
    look like a real Nuclei template first) — this is how Nuclei itself
    resolves workflow steps, not by template id.
    """
    if not template_paths:
        raise BuildError("At least one template is required to build a workflow")

    for path in template_paths:
        _validate_template_file(path)

    return {
        "id": slugify_id(workflow_id),
        "info": {"name": name, "author": author},
        "workflows": [{"template": str(path)} for path in template_paths],
    }


def to_yaml(workflow: dict[str, Any]) -> str:
    """Serialize a workflow dict to clean YAML."""
    return yaml.safe_dump(workflow, sort_keys=False, default_flow_style=False, allow_unicode=True, width=120)

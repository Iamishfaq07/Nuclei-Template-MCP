"""Improve an existing Nuclei template via the improver prompt.

This backs the `improve` command: it takes a template a user already has
(hand-written or previously generated), optionally the original request for
context, runs it through `prompts/template_improver.txt`, and rebuilds a
clean, validated template from the model's response.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from mcp_nuclei.core import builder
from mcp_nuclei.core.generator import GenerationError, GenerationResult, load_prompt
from mcp_nuclei.core.importers import import_file
from mcp_nuclei.core.parser import ParseError
from mcp_nuclei.mcp.client import MCPClient
from mcp_nuclei.utils.http import to_raw_nuclei_block


def improve_template(
    *,
    template_path: Path,
    client: MCPClient,
    request_path: Optional[Path] = None,
    fmt: str = "auto",
) -> GenerationResult:
    """Load an existing template, run it through the improver, and rebuild it."""
    if not template_path.exists():
        raise GenerationError(f"Template file not found: {template_path}")

    original_yaml = template_path.read_text(encoding="utf-8")
    if not original_yaml.strip():
        raise GenerationError(f"Template file is empty: {template_path}")

    sections = [
        "## Existing Nuclei template to review and improve",
        "```yaml",
        original_yaml.strip(),
        "```",
    ]

    if request_path is not None:
        try:
            captures = import_file(request_path, fmt=fmt)
        except ParseError as exc:
            raise GenerationError(str(exc)) from exc
        if captures:
            sections += [
                "",
                "## Original HTTP request the template was derived from (for context)",
                "```http",
                to_raw_nuclei_block(captures[0].request),
                "```",
            ]

    system = load_prompt("template_improver.txt")
    user = "\n".join(sections)

    try:
        raw_output = client.generate(system_prompt=system, user_prompt=user)
    except Exception as exc:
        raise GenerationError(f"MCP client failed during improvement: {exc}") from exc

    if not raw_output or not raw_output.strip():
        raise GenerationError("MCP client returned an empty response")

    try:
        data = builder.parse_template_yaml(raw_output)
        # Reuse whatever the model kept for id/info; only fill gaps.
        normalized = builder.normalize_template(data, fallback_name="improved-template")
        builder.validate_template(normalized)
        template_yaml = builder.to_yaml(normalized)
    except builder.BuildError as exc:
        raise GenerationError(str(exc)) from exc

    return GenerationResult(
        template_yaml=template_yaml,
        template_dict=normalized,
        detected_type=None,
        raw_mcp_output=raw_output,
        label=template_path.name,
        refined=True,
    )

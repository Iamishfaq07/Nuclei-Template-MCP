"""High-level orchestration: parse request -> prompt MCP -> build template.

This is the only module that ties parsing, prompting, MCP, and building
together, so the CLI stays a thin wrapper around `generate_template()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mcp_nuclei.core import builder
from mcp_nuclei.core.parser import (
    HttpRequest,
    HttpResponse,
    ParseError,
    parse_request_file,
    parse_response_file,
)
from mcp_nuclei.mcp.client import MCPClient
from mcp_nuclei.utils.http import to_raw_nuclei_block

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

# Maps a detected/forced vulnerability type to its specialised prompt file.
VULN_TYPE_PROMPTS: dict[str, str] = {
    "idor": "idor.txt",
    "sqli": "sqli.txt",
    "xss": "xss.txt",
}

# Keywords used to auto-detect a vulnerability type from a free-text description.
_VULN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "idor": ("idor", "insecure direct object", "object reference", "broken object level"),
    "sqli": ("sql injection", "sqli", "sql-injection", "union select", "blind sql"),
    "xss": ("xss", "cross-site scripting", "cross site scripting", "script injection"),
}


class GenerationError(Exception):
    """Raised when the end-to-end generation pipeline fails."""


@dataclass
class GenerationResult:
    """The output of a successful `generate_template()` call."""

    template_yaml: str
    template_dict: dict
    detected_type: Optional[str]
    raw_mcp_output: str


def detect_vuln_type(description: Optional[str]) -> Optional[str]:
    """Best-effort detection of a known vulnerability type from a free-text description."""
    if not description:
        return None
    lowered = description.lower()
    for vuln_type, keywords in _VULN_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return vuln_type
    return None


def load_prompt(name: str) -> str:
    """Read a prompt file from the packaged `prompts/` directory."""
    path = PROMPTS_DIR / name
    if not path.exists():
        raise GenerationError(f"Prompt file not found: {path}")
    return path.read_text(encoding="utf-8")


def build_system_prompt(vuln_type: Optional[str]) -> str:
    """Combine the base system prompt with a specialised one, if applicable."""
    base = load_prompt("base.txt")
    prompt_file = VULN_TYPE_PROMPTS.get(vuln_type) if vuln_type else None
    if not prompt_file:
        return base
    return f"{base}\n\n---\n\n{load_prompt(prompt_file)}"


def build_user_prompt(
    request: HttpRequest,
    response: Optional[HttpResponse],
    description: Optional[str],
) -> str:
    """Render the parsed request/response/description into the MCP user prompt."""
    sections = ["## Raw HTTP Request", "```http", to_raw_nuclei_block(request), "```"]

    if response is not None:
        sections += [
            "",
            "## Observed HTTP Response",
            f"Status: {response.status_code} {response.reason}".strip(),
            "```http",
            response.raw.strip(),
            "```",
        ]

    if description:
        sections += ["", "## Vulnerability Description (provided by the analyst)", description]

    sections += [
        "",
        "## Task",
        "Analyze the request/response above and produce a single, production-ready "
        "Nuclei YAML template that reliably detects this vulnerability. "
        "Respond with ONLY the YAML template and nothing else.",
    ]
    return "\n".join(sections)


def generate_template(
    *,
    request_path: Path,
    client: MCPClient,
    response_path: Optional[Path] = None,
    description: Optional[str] = None,
    vuln_type: Optional[str] = None,
    template_id: Optional[str] = None,
    author: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
) -> GenerationResult:
    """Run the full parse -> prompt -> MCP -> build pipeline for one request."""
    try:
        request = parse_request_file(request_path)
        response = parse_response_file(response_path) if response_path else None
    except ParseError as exc:
        raise GenerationError(str(exc)) from exc

    detected_type = vuln_type or detect_vuln_type(description)
    system_prompt = build_system_prompt(detected_type)
    user_prompt = build_user_prompt(request, response, description)

    try:
        raw_output = client.generate(system_prompt=system_prompt, user_prompt=user_prompt)
    except Exception as exc:
        raise GenerationError(f"MCP client failed to generate a response: {exc}") from exc

    if not raw_output or not raw_output.strip():
        raise GenerationError("MCP client returned an empty response")

    fallback_name = description or template_id or f"{request.method} {request.path}"

    try:
        data = builder.parse_template_yaml(raw_output)
        normalized = builder.normalize_template(
            data,
            fallback_name=fallback_name,
            default_author=author or "mcp-nuclei",
            default_severity=severity or "medium",
            tags=tags,
        )
        if template_id:
            normalized["id"] = builder.slugify_id(template_id)
        builder.validate_template(normalized)
        template_yaml = builder.to_yaml(normalized)
    except builder.BuildError as exc:
        raise GenerationError(str(exc)) from exc

    return GenerationResult(
        template_yaml=template_yaml,
        template_dict=normalized,
        detected_type=detected_type,
        raw_mcp_output=raw_output,
    )

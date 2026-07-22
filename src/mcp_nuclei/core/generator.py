"""High-level orchestration: parse request -> prompt MCP -> build template.

This is the only module that ties parsing, importing, prompting, MCP, and
building together, so the CLI stays a thin wrapper around
`generate_template()` / `generate_from_capture()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mcp_nuclei.core import builder
from mcp_nuclei.core.importers import RequestCapture, import_file
from mcp_nuclei.core.parser import (
    HttpRequest,
    HttpResponse,
    ParseError,
    parse_response_file,
)
from mcp_nuclei.core.plugins import load_plugin_prompts
from mcp_nuclei.mcp.client import MCPClient
from mcp_nuclei.utils.http import to_raw_nuclei_block

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

# Maps a detected/forced vulnerability type to its specialised prompt file.
VULN_TYPE_PROMPTS: dict[str, str] = {
    "idor": "idor.txt",
    "sqli": "sqli.txt",
    "xss": "xss.txt",
    "ssrf": "ssrf.txt",
    "xxe": "xxe.txt",
    "lfi": "lfi.txt",
    "open-redirect": "open-redirect.txt",
    "ssti": "ssti.txt",
    "auth-bypass": "auth-bypass.txt",
    "cors": "cors.txt",
    "cmdi": "cmdi.txt",
}

# Keywords used to auto-detect a vulnerability type from a free-text description.
_VULN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "idor": ("idor", "insecure direct object", "object reference", "broken object level"),
    "sqli": ("sql injection", "sqli", "sql-injection", "union select", "blind sql"),
    "xss": ("xss", "cross-site scripting", "cross site scripting", "script injection"),
    "ssrf": ("ssrf", "server-side request forgery", "server side request forgery"),
    "xxe": ("xxe", "xml external entity", "external entity"),
    "lfi": ("lfi", "local file inclusion", "path traversal", "directory traversal"),
    "open-redirect": ("open redirect", "open-redirect", "unvalidated redirect"),
    "ssti": ("ssti", "template injection", "server-side template"),
    "auth-bypass": ("auth bypass", "authentication bypass", "authorization bypass", "access control"),
    "cors": ("cors", "cross-origin", "access-control-allow-origin"),
    "cmdi": ("command injection", "cmdi", "os command", "rce via command", "shell injection"),
}


def register_plugin_prompts() -> list[str]:
    """Merge any discovered plugin vuln-type prompts into the built-in tables.

    Returns the vuln_type keys that were added/overridden, for logging or
    tests. Safe to call more than once (idempotent per plugin vuln_type).
    """
    added: list[str] = []
    for plugin in load_plugin_prompts():
        VULN_TYPE_PROMPTS[plugin.vuln_type] = str(plugin.prompt_path)
        if plugin.keywords:
            _VULN_KEYWORDS[plugin.vuln_type] = tuple(plugin.keywords)
        added.append(plugin.vuln_type)
    return added


register_plugin_prompts()


class GenerationError(Exception):
    """Raised when the end-to-end generation pipeline fails."""


@dataclass
class GenerationResult:
    """The output of a successful `generate_template()` call."""

    template_yaml: str
    template_dict: dict
    detected_type: Optional[str]
    raw_mcp_output: str
    label: Optional[str] = None
    refined: bool = False


@dataclass
class PreparedPrompt:
    """The assembled prompts for a dry-run, without calling MCP."""

    system_prompt: str
    user_prompt: str
    detected_type: Optional[str]


def detect_vuln_type(description: Optional[str]) -> Optional[str]:
    """Best-effort detection of a known vulnerability type from a free-text description."""
    if not description:
        return None
    lowered = description.lower()
    for vuln_type, keywords in _VULN_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return vuln_type
    return None


def classify_with_mcp(
    request: HttpRequest,
    response: Optional[HttpResponse],
    client: MCPClient,
) -> Optional[str]:
    """Ask MCP to classify the vulnerability type when no hint is available.

    Returns one of the keys of `VULN_TYPE_PROMPTS`, or None if the model
    can't confidently classify it (in which case only the base prompt is
    used).
    """
    valid = ", ".join(sorted(VULN_TYPE_PROMPTS))
    system = (
        "You are a security classifier. Given an HTTP request (and optional "
        "response), reply with EXACTLY ONE token naming the most likely "
        f"vulnerability class from this list: {valid}. If none clearly "
        "applies, reply with the single token 'none'. Reply with only the "
        "token, no punctuation or explanation."
    )
    user = build_user_prompt(request, response, description=None, task=None)
    try:
        raw = client.generate(system_prompt=system, user_prompt=user)
    except Exception:
        return None

    token = raw.strip().lower().split()[0].strip(".,`'\"") if raw.strip() else ""
    return token if token in VULN_TYPE_PROMPTS else None


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
    task: Optional[str] = (
        "Analyze the request/response above and produce a single, production-ready "
        "Nuclei YAML template that reliably detects this vulnerability. "
        "Respond with ONLY the YAML template and nothing else."
    ),
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

    if task:
        sections += ["", "## Task", task]
    return "\n".join(sections)


def build_prepared_prompt(
    *,
    request: HttpRequest,
    response: Optional[HttpResponse] = None,
    description: Optional[str] = None,
    vuln_type: Optional[str] = None,
) -> PreparedPrompt:
    """Assemble the system/user prompts for inspection (used by --dry-run)."""
    detected_type = vuln_type or detect_vuln_type(description)
    return PreparedPrompt(
        system_prompt=build_system_prompt(detected_type),
        user_prompt=build_user_prompt(request, response, description),
        detected_type=detected_type,
    )


def _build_result(
    raw_output: str,
    *,
    request: HttpRequest,
    description: Optional[str],
    template_id: Optional[str],
    author: Optional[str],
    severity: Optional[str],
    tags: Optional[str],
    detected_type: Optional[str],
    label: Optional[str],
    refined: bool,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
) -> GenerationResult:
    """Normalize + validate MCP output into a `GenerationResult`."""
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
            cve_id=cve_id,
            cwe_id=cwe_id,
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
        label=label,
        refined=refined,
    )


def refine_template(template_yaml: str, client: MCPClient) -> str:
    """Run a template through the improver prompt for a self-critique pass."""
    system = load_prompt("template_improver.txt")
    user = f"## Existing Nuclei template to review and improve\n```yaml\n{template_yaml}\n```"
    try:
        return client.generate(system_prompt=system, user_prompt=user)
    except Exception as exc:
        raise GenerationError(f"MCP client failed during refinement: {exc}") from exc


def explain_template(template_yaml: str, request: HttpRequest, client: MCPClient) -> str:
    """Ask MCP for a short, plain-language rationale for a generated template.

    This is a separate, lightweight call (not embedded in the template
    itself) so the explanation can be shown in the terminal for a human
    reviewer without polluting the YAML output.
    """
    system = (
        "You are a security engineer explaining a Nuclei template to a teammate. "
        "In 3-5 concise sentences, explain: (1) why the matchers/extractors chosen "
        "prove the vulnerability rather than producing a false positive, and "
        "(2) any notable trade-off or limitation of the template. "
        "Plain prose only, no YAML, no headers, no bullet points."
    )
    user = (
        f"## Original request\n```http\n{to_raw_nuclei_block(request)}\n```\n\n"
        f"## Generated template\n```yaml\n{template_yaml}\n```"
    )
    try:
        return client.generate(system_prompt=system, user_prompt=user).strip()
    except Exception as exc:
        raise GenerationError(f"MCP client failed while generating an explanation: {exc}") from exc


def generate_from_capture(
    capture: RequestCapture,
    *,
    client: MCPClient,
    description: Optional[str] = None,
    vuln_type: Optional[str] = None,
    template_id: Optional[str] = None,
    author: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[str] = None,
    auto_classify: bool = False,
    refine: bool = False,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
) -> GenerationResult:
    """Run the generation pipeline for an already-parsed `RequestCapture`."""
    request, response = capture.request, capture.response

    detected_type = vuln_type or detect_vuln_type(description)
    if detected_type is None and auto_classify:
        detected_type = classify_with_mcp(request, response, client)

    system_prompt = build_system_prompt(detected_type)
    user_prompt = build_user_prompt(request, response, description)

    try:
        raw_output = client.generate(system_prompt=system_prompt, user_prompt=user_prompt)
    except Exception as exc:
        raise GenerationError(f"MCP client failed to generate a response: {exc}") from exc

    result = _build_result(
        raw_output,
        request=request,
        description=description,
        template_id=template_id,
        author=author,
        severity=severity,
        tags=tags,
        detected_type=detected_type,
        label=capture.label,
        refined=False,
        cve_id=cve_id,
        cwe_id=cwe_id,
    )

    if refine:
        refined_output = refine_template(result.template_yaml, client)
        result = _build_result(
            refined_output,
            request=request,
            description=description,
            template_id=template_id,
            author=author,
            severity=severity,
            tags=tags,
            detected_type=detected_type,
            label=capture.label,
            refined=True,
            cve_id=cve_id,
            cwe_id=cwe_id,
        )

    return result


def load_captures(
    input_path: Path,
    *,
    response_path: Optional[Path] = None,
    fmt: str = "auto",
) -> list[RequestCapture]:
    """Load one or more `RequestCapture`s from an input file.

    For the default `raw` format an optional separate response file may be
    supplied; multi-request formats (HAR, Burp) carry their own responses.
    """
    try:
        captures = import_file(input_path, fmt=fmt)
    except ParseError as exc:
        raise GenerationError(str(exc)) from exc

    if response_path is not None and captures:
        try:
            captures[0].response = parse_response_file(response_path)
        except ParseError as exc:
            raise GenerationError(str(exc)) from exc
    return captures


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
    fmt: str = "auto",
    auto_classify: bool = False,
    refine: bool = False,
) -> GenerationResult:
    """Run the full import -> prompt -> MCP -> build pipeline for one request.

    This convenience wrapper imports the first capture from `request_path`
    (which may be raw/curl/HAR/Burp) and generates a single template.
    """
    captures = load_captures(request_path, response_path=response_path, fmt=fmt)
    if not captures:
        raise GenerationError(f"No requests could be loaded from {request_path}")

    return generate_from_capture(
        captures[0],
        client=client,
        description=description,
        vuln_type=vuln_type,
        template_id=template_id,
        author=author,
        severity=severity,
        tags=tags,
        auto_classify=auto_classify,
        refine=refine,
    )

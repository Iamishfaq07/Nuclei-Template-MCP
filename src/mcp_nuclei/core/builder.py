"""Build, normalize, and validate final Nuclei YAML templates.

This module never talks to MCP. It only knows how to turn the (possibly
messy) text an LLM produced into a well-formed, valid Nuclei template: it
strips markdown fences, fills in missing required fields with sane
defaults, validates the result, and serializes it back to clean YAML.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml
from pydantic import BaseModel, field_validator

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
PROTOCOL_BLOCKS = ("http", "network", "dns", "file", "headless", "ssl", "websocket")
_YAML_FENCE_RE = re.compile(r"```(?:ya?ml)?\s*\n(.*?)```", re.DOTALL)
_SLUG_RE = re.compile(r"[^a-zA-Z0-9]+")


class BuildError(Exception):
    """Raised when a Nuclei template cannot be built or fails validation."""


class TemplateInfo(BaseModel):
    """The `info` block of a Nuclei template."""

    name: str
    author: str = "mcp-nuclei"
    severity: str = "medium"
    description: Optional[str] = None
    tags: Optional[str] = None
    reference: Optional[list[str]] = None
    classification: Optional[dict[str, Any]] = None

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, value: str) -> str:
        if value.lower() not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {value!r}, expected one of {sorted(VALID_SEVERITIES)}")
        return value.lower()


def slugify_id(text: str) -> str:
    """Turn arbitrary text into a valid Nuclei template id (kebab-case, alnum + dashes)."""
    slug = _SLUG_RE.sub("-", text.strip()).strip("-").lower()
    slug = re.sub(r"-{2,}", "-", slug)
    return slug or "generated-template"


def extract_yaml_block(raw_text: str) -> str:
    """Strip a surrounding Markdown code fence, if the model wrapped its output in one."""
    text = raw_text.strip()
    match = _YAML_FENCE_RE.search(text)
    return match.group(1).strip() if match else text


def parse_template_yaml(raw_text: str) -> dict[str, Any]:
    """Parse MCP's raw text output into a template dict."""
    cleaned = extract_yaml_block(raw_text)
    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError as exc:
        raise BuildError(f"MCP output is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise BuildError("MCP output did not produce a YAML mapping at the top level")
    return data


def normalize_template(
    data: dict[str, Any],
    *,
    fallback_name: str,
    default_author: str = "mcp-nuclei",
    default_severity: str = "medium",
    tags: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
) -> dict[str, Any]:
    """Fill in missing required fields and normalize the template's structure."""
    template = dict(data)

    info = dict(template.get("info") or {})
    info.setdefault("name", fallback_name)
    info.setdefault("author", default_author)
    info.setdefault("severity", default_severity)

    if tags:
        existing = {t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()}
        requested = {t.strip() for t in tags.split(",") if t.strip()}
        info["tags"] = ",".join(sorted(existing | requested))

    if cve_id or cwe_id:
        classification = dict(info.get("classification") or {})
        if cve_id:
            classification["cve-id"] = cve_id.lower()
        if cwe_id:
            classification["cwe-id"] = cwe_id.lower()
        info["classification"] = classification

    try:
        info_model = TemplateInfo(**info)
    except Exception as exc:
        raise BuildError(f"Invalid 'info' block: {exc}") from exc
    template["info"] = info_model.model_dump(exclude_none=True)

    template["id"] = slugify_id(str(template["id"])) if template.get("id") else slugify_id(fallback_name)

    # Some models emit "requests" (an older/alternate key) instead of "http".
    if "requests" in template and "http" not in template:
        template["http"] = template.pop("requests")

    return template


def validate_template(template: dict[str, Any]) -> None:
    """Raise `BuildError` if the template is missing required structure."""
    missing = [f for f in ("id", "info") if f not in template]
    if missing:
        raise BuildError(f"Template is missing required field(s): {', '.join(missing)}")

    if not any(block in template for block in PROTOCOL_BLOCKS):
        raise BuildError(
            "Template is missing a protocol block (expected one of: "
            f"{', '.join(PROTOCOL_BLOCKS)}). MCP output could not be turned into a runnable template."
        )


def to_yaml(template: dict[str, Any]) -> str:
    """Serialize a template dict to clean, deterministically-ordered YAML."""
    preferred_order = ["id", "info", *PROTOCOL_BLOCKS]
    ordered: dict[str, Any] = {}
    for key in preferred_order:
        if key in template:
            ordered[key] = template[key]
    for key, value in template.items():
        if key not in ordered:
            ordered[key] = value

    return yaml.safe_dump(
        ordered,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
    )

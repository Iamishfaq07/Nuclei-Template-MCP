"""Parsing of raw HTTP request/response files into structured models.

These models are the input context that gets handed to MCP for reasoning,
and (for the request) rendered back into a Nuclei `raw` request block.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from mcp_nuclei.utils.http import (
    MalformedHttpError,
    parse_headers,
    split_head_body,
    split_request_line,
    split_status_line,
)


class ParseError(Exception):
    """Raised when a request/response file cannot be parsed."""


class HttpMessage(BaseModel):
    """Base fields shared by parsed HTTP requests and responses."""

    raw: str = Field(..., description="The original raw text, unmodified.")
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""


class HttpRequest(HttpMessage):
    """A parsed raw HTTP request."""

    method: str
    path: str
    http_version: str = "HTTP/1.1"
    host: Optional[str] = None
    scheme: str = "https"

    @property
    def url(self) -> str:
        """Best-effort absolute URL, falling back to the Nuclei `{{Hostname}}` variable."""
        host = self.host or "{{Hostname}}"
        return f"{self.scheme}://{host}{self.path}"


class HttpResponse(HttpMessage):
    """A parsed raw HTTP response."""

    status_code: int
    reason: str = ""


def parse_request_file(path: Path) -> HttpRequest:
    """Parse a raw HTTP request file (e.g. exported from Burp Suite) into an `HttpRequest`."""
    if not path.exists():
        raise ParseError(f"Request file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        raise ParseError(f"Request file is empty: {path}")

    head, body = split_head_body(raw)
    lines = head.split("\n")

    try:
        method, request_path, version = split_request_line(lines[0])
    except MalformedHttpError as exc:
        raise ParseError(f"Could not parse {path}: {exc}") from exc

    headers = parse_headers(lines[1:])
    host = headers.get("Host") or headers.get("host")
    scheme = "http" if request_path.lower().startswith("http://") else "https"

    return HttpRequest(
        raw=raw,
        method=method.upper(),
        path=request_path,
        http_version=version,
        headers=headers,
        body=body.strip("\n"),
        host=host,
        scheme=scheme,
    )


def parse_response_file(path: Path) -> HttpResponse:
    """Parse a raw HTTP response file into an `HttpResponse`."""
    if not path.exists():
        raise ParseError(f"Response file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        raise ParseError(f"Response file is empty: {path}")

    head, body = split_head_body(raw)
    lines = head.split("\n")

    try:
        _, status_code, reason = split_status_line(lines[0])
    except MalformedHttpError as exc:
        raise ParseError(f"Could not parse {path}: {exc}") from exc

    headers = parse_headers(lines[1:])

    return HttpResponse(
        raw=raw,
        status_code=status_code,
        reason=reason,
        headers=headers,
        body=body.strip("\n"),
    )

"""Low-level helpers for working with raw HTTP request/response text.

These functions operate on plain strings only, so they stay easy to unit
test and have no knowledge of Nuclei or MCP specifics. Higher level parsing
(into `HttpRequest` / `HttpResponse` models) lives in `mcp_nuclei.core.parser`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_nuclei.core.parser import HttpRequest


class MalformedHttpError(ValueError):
    """Raised when raw HTTP text cannot be split into a line, headers, and body."""


def split_head_body(raw: str) -> tuple[str, str]:
    """Split raw HTTP text into the head (request/status line + headers) and body."""
    normalized = raw.replace("\r\n", "\n")
    if "\n\n" in normalized:
        head, _, body = normalized.partition("\n\n")
    else:
        head, body = normalized, ""
    return head, body


def parse_headers(header_lines: list[str]) -> dict[str, str]:
    """Parse a list of `Header: value` lines into a dict, preserving order."""
    headers: dict[str, str] = {}
    for line in header_lines:
        if not line.strip() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def split_request_line(line: str) -> tuple[str, str, str]:
    """Split a request line into (method, path, http_version)."""
    parts = line.strip().split(" ")
    if len(parts) < 2:
        raise MalformedHttpError(f"Invalid HTTP request line: {line!r}")
    method, path = parts[0], parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    return method, path, version


def split_status_line(line: str) -> tuple[str, int, str]:
    """Split a status line into (http_version, status_code, reason)."""
    parts = line.strip().split(" ", 2)
    if len(parts) < 2:
        raise MalformedHttpError(f"Invalid HTTP status line: {line!r}")
    version = parts[0]
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise MalformedHttpError(f"Invalid status code in line: {line!r}") from exc
    reason = parts[2] if len(parts) > 2 else ""
    return version, status_code, reason


def to_raw_nuclei_block(request: "HttpRequest") -> str:
    """Render a parsed request back into a Nuclei `raw` request block."""
    lines = [f"{request.method} {request.path} {request.http_version}"]
    for key, value in request.headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    if request.body:
        lines.append(request.body)
    return "\n".join(lines)

"""Importers that turn various capture formats into `HttpRequest`/`HttpResponse`.

The raw `.req`/`.resp` parsing lives in `parser.py`. This module adds the
formats security folks actually export from their tooling:

- **curl** command strings (`curl -X POST ... -H ... -d ...`)
- **HAR** files (browser DevTools / Charles / Fiddler exports)
- **Burp Suite** XML exports (base64-encoded request/response pairs)

Each importer returns one or more `RequestCapture` objects, pairing a
parsed request with its optional response, so the same downstream
generation pipeline works regardless of input format.
"""
from __future__ import annotations

import base64
import binascii
import json
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from mcp_nuclei.core.parser import (
    HttpRequest,
    HttpResponse,
    ParseError,
    _parse_request_text,
    _parse_response_text,
)


@dataclass
class RequestCapture:
    """A parsed request paired with its optional response and a source label."""

    request: HttpRequest
    response: Optional[HttpResponse] = None
    label: Optional[str] = None


# Formats we can auto-detect and import.
SUPPORTED_FORMATS = ("raw", "curl", "har", "burp")


def detect_format(path: Path) -> str:
    """Best-effort detection of a capture file's format from its suffix/content."""
    suffix = path.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix == ".xml":
        return "burp"

    text = path.read_text(encoding="utf-8", errors="replace").lstrip()
    if not text:
        raise ParseError(f"File is empty: {path}")
    if text.startswith("{") and '"log"' in text[:2000]:
        return "har"
    if text.startswith("<") and "burp" in text[:500].lower():
        return "burp"
    if text.startswith("curl ") or text.startswith("curl\t"):
        return "curl"
    return "raw"


def import_file(path: Path, fmt: str = "auto") -> list[RequestCapture]:
    """Import a capture file into one or more `RequestCapture`s.

    `fmt` may be one of `SUPPORTED_FORMATS` or `"auto"` to detect from the file.
    """
    if not path.exists():
        raise ParseError(f"File not found: {path}")

    resolved = detect_format(path) if fmt == "auto" else fmt
    text = path.read_text(encoding="utf-8", errors="replace")

    if resolved == "raw":
        request = _parse_request_text(text, source=str(path))
        return [RequestCapture(request=request, label=path.name)]
    if resolved == "curl":
        return [RequestCapture(request=parse_curl(text), label=path.name)]
    if resolved == "har":
        return parse_har(text)
    if resolved == "burp":
        return parse_burp_xml(text)

    raise ParseError(f"Unknown format {resolved!r}; expected one of {SUPPORTED_FORMATS} or 'auto'")


# --------------------------------------------------------------------------- #
# curl
# --------------------------------------------------------------------------- #

_CURL_METHOD_FLAGS = {"-X", "--request"}
_CURL_HEADER_FLAGS = {"-H", "--header"}
_CURL_DATA_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii"}


def parse_curl(command: str) -> HttpRequest:
    """Parse a `curl` command string into an `HttpRequest`."""
    # Normalise line continuations so shlex sees one logical command.
    normalized = command.strip()
    if normalized.startswith("curl"):
        normalized = normalized[len("curl"):]
    normalized = normalized.replace("\\\n", " ").replace("\\\r\n", " ")

    try:
        tokens = shlex.split(normalized)
    except ValueError as exc:
        raise ParseError(f"Could not tokenize curl command: {exc}") from exc

    method: Optional[str] = None
    headers: dict[str, str] = {}
    body_parts: list[str] = []
    url: Optional[str] = None

    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in _CURL_METHOD_FLAGS:
            method = tokens[i + 1].upper() if i + 1 < len(tokens) else method
            i += 2
            continue
        if token in _CURL_HEADER_FLAGS and i + 1 < len(tokens):
            key, _, value = tokens[i + 1].partition(":")
            headers[key.strip()] = value.strip()
            i += 2
            continue
        if token in _CURL_DATA_FLAGS and i + 1 < len(tokens):
            body_parts.append(tokens[i + 1])
            i += 2
            continue
        if token in {"--url"} and i + 1 < len(tokens):
            url = tokens[i + 1]
            i += 2
            continue
        if token.startswith("-"):
            # Skip unknown flags; consume a value if it doesn't look like a flag.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") and token not in {"-L", "-k", "-s", "-v", "--compressed", "--insecure", "--location"}:
                i += 2
            else:
                i += 1
            continue
        if url is None and (token.startswith("http://") or token.startswith("https://") or "." in token):
            url = token
        i += 1

    if url is None:
        raise ParseError("Could not find a URL in the curl command")

    body = "&".join(body_parts) if body_parts else ""
    if method is None:
        method = "POST" if body else "GET"

    split = urlsplit(url if "://" in url else f"https://{url}")
    path = split.path or "/"
    if split.query:
        path = f"{path}?{split.query}"
    headers.setdefault("Host", split.netloc)

    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = f"{method} {path} HTTP/1.1\n{header_lines}\n\n{body}".strip() + "\n"
    request = _parse_request_text(raw, source="curl")
    request.scheme = split.scheme or "https"
    return request


# --------------------------------------------------------------------------- #
# HAR
# --------------------------------------------------------------------------- #


def parse_har(text: str) -> list[RequestCapture]:
    """Parse a HAR (HTTP Archive) JSON document into `RequestCapture`s."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid HAR JSON: {exc}") from exc

    entries = (data.get("log") or {}).get("entries")
    if not entries:
        raise ParseError("HAR file contains no entries under log.entries")

    captures: list[RequestCapture] = []
    for index, entry in enumerate(entries):
        req = entry.get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url") or ""
        if not url:
            continue

        split = urlsplit(url)
        path = split.path or "/"
        if split.query:
            path = f"{path}?{split.query}"

        headers = {h["name"]: h.get("value", "") for h in req.get("headers", []) if h.get("name")}
        headers.setdefault("Host", split.netloc)
        body = (req.get("postData") or {}).get("text", "")

        header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
        raw_req = f"{method} {path} HTTP/1.1\n{header_lines}\n\n{body}".strip() + "\n"
        request = _parse_request_text(raw_req, source=f"har[{index}]")
        request.scheme = split.scheme or "https"

        response = _har_response(entry.get("response"))
        captures.append(RequestCapture(request=request, response=response, label=f"{method} {path}"))

    if not captures:
        raise ParseError("HAR file did not yield any usable requests")
    return captures


def _har_response(resp: Optional[dict]) -> Optional[HttpResponse]:
    """Turn a HAR response object into an `HttpResponse`, if present."""
    if not resp or not resp.get("status"):
        return None
    status = int(resp.get("status", 0))
    reason = resp.get("statusText", "")
    headers = {h["name"]: h.get("value", "") for h in resp.get("headers", []) if h.get("name")}
    body = (resp.get("content") or {}).get("text", "")
    header_lines = "\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = f"HTTP/1.1 {status} {reason}\n{header_lines}\n\n{body}".strip() + "\n"
    try:
        return _parse_response_text(raw, source="har-response")
    except ParseError:
        return None


# --------------------------------------------------------------------------- #
# Burp Suite XML
# --------------------------------------------------------------------------- #


def parse_burp_xml(text: str) -> list[RequestCapture]:
    """Parse a Burp Suite XML export into `RequestCapture`s.

    Burp exports a top-level `<items>` element with `<item>` children, each
    holding `<request>` and `<response>` elements that may be base64-encoded
    (`base64="true"`).
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParseError(f"Invalid Burp XML: {exc}") from exc

    items = root.findall(".//item")
    if not items:
        raise ParseError("Burp XML contains no <item> elements")

    captures: list[RequestCapture] = []
    for index, item in enumerate(items):
        req_el = item.find("request")
        if req_el is None or not (req_el.text or "").strip():
            continue

        raw_req = _decode_burp_field(req_el)
        try:
            request = _parse_request_text(raw_req, source=f"burp[{index}]")
        except ParseError:
            continue

        # Burp stores host/protocol separately; use them if present.
        host_el = item.find("host")
        if host_el is not None and host_el.text:
            request.host = host_el.text.strip()
            request.headers.setdefault("Host", request.host)
        proto_el = item.find("protocol")
        if proto_el is not None and proto_el.text:
            request.scheme = proto_el.text.strip()

        response = None
        resp_el = item.find("response")
        if resp_el is not None and (resp_el.text or "").strip():
            try:
                response = _parse_response_text(_decode_burp_field(resp_el), source=f"burp-resp[{index}]")
            except ParseError:
                response = None

        url_el = item.find("url")
        label = url_el.text.strip() if url_el is not None and url_el.text else f"item {index}"
        captures.append(RequestCapture(request=request, response=response, label=label))

    if not captures:
        raise ParseError("Burp XML did not yield any usable requests")
    return captures


def _decode_burp_field(element: ET.Element) -> str:
    """Return the (possibly base64-decoded) text content of a Burp element."""
    raw = element.text or ""
    if element.get("base64") == "true":
        try:
            return base64.b64decode(raw).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError) as exc:
            raise ParseError(f"Could not base64-decode Burp field: {exc}") from exc
    return raw

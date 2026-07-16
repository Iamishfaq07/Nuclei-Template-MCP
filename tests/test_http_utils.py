import pytest

from mcp_nuclei.utils.http import (
    MalformedHttpError,
    parse_headers,
    split_head_body,
    split_request_line,
    split_status_line,
)


def test_split_head_body_separates_on_blank_line():
    raw = "GET / HTTP/1.1\nHost: example.com\n\n{\"a\": 1}"
    head, body = split_head_body(raw)
    assert head == "GET / HTTP/1.1\nHost: example.com"
    assert body == '{"a": 1}'


def test_split_head_body_handles_crlf():
    raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"
    head, body = split_head_body(raw)
    assert head == "GET / HTTP/1.1\nHost: example.com"
    assert body == "body"


def test_split_head_body_no_body():
    raw = "GET / HTTP/1.1\nHost: example.com"
    head, body = split_head_body(raw)
    assert head == raw
    assert body == ""


def test_parse_headers_basic():
    headers = parse_headers(["Host: example.com", "Content-Type: application/json", "", "Malformed"])
    assert headers == {"Host": "example.com", "Content-Type": "application/json"}


def test_split_request_line():
    method, path, version = split_request_line("GET /api/v1/orders/1 HTTP/1.1")
    assert (method, path, version) == ("GET", "/api/v1/orders/1", "HTTP/1.1")


def test_split_request_line_defaults_version():
    method, path, version = split_request_line("GET /path")
    assert (method, path, version) == ("GET", "/path", "HTTP/1.1")


def test_split_request_line_invalid_raises():
    with pytest.raises(MalformedHttpError):
        split_request_line("garbage")


def test_split_status_line():
    version, status, reason = split_status_line("HTTP/1.1 200 OK")
    assert (version, status, reason) == ("HTTP/1.1", 200, "OK")


def test_split_status_line_invalid_status_raises():
    with pytest.raises(MalformedHttpError):
        split_status_line("HTTP/1.1 notanumber OK")

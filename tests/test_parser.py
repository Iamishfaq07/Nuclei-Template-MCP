from pathlib import Path

import pytest

from mcp_nuclei.core.parser import ParseError, parse_request_file, parse_response_file


def test_parse_request_file(tmp_path: Path):
    req = tmp_path / "sample.req"
    req.write_text(
        "GET /api/v1/orders/2001 HTTP/1.1\n"
        "Host: shop.example.com\n"
        "Authorization: Bearer token123\n"
        "\n"
    )

    parsed = parse_request_file(req)

    assert parsed.method == "GET"
    assert parsed.path == "/api/v1/orders/2001"
    assert parsed.headers["Host"] == "shop.example.com"
    assert parsed.headers["Authorization"] == "Bearer token123"
    assert parsed.host == "shop.example.com"
    assert parsed.url == "https://shop.example.com/api/v1/orders/2001"


def test_parse_request_file_with_body(tmp_path: Path):
    req = tmp_path / "sample.req"
    req.write_text(
        "POST /login HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "\n"
        '{"user": "admin", "pass": "x"}'
    )

    parsed = parse_request_file(req)
    assert parsed.body == '{"user": "admin", "pass": "x"}'


def test_parse_request_file_missing_raises():
    with pytest.raises(ParseError):
        parse_request_file(Path("/nonexistent/path.req"))


def test_parse_request_file_empty_raises(tmp_path: Path):
    req = tmp_path / "empty.req"
    req.write_text("   ")
    with pytest.raises(ParseError):
        parse_request_file(req)


def test_parse_response_file(tmp_path: Path):
    resp = tmp_path / "sample.resp"
    resp.write_text("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\": true}")

    parsed = parse_response_file(resp)
    assert parsed.status_code == 200
    assert parsed.reason == "OK"
    assert parsed.headers["Content-Type"] == "application/json"
    assert parsed.body == '{"ok": true}'

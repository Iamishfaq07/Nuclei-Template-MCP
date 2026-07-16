import base64
import json
from pathlib import Path

import pytest

from mcp_nuclei.core.importers import (
    detect_format,
    import_file,
    parse_burp_xml,
    parse_curl,
    parse_har,
)
from mcp_nuclei.core.parser import ParseError


def test_parse_curl_basic():
    req = parse_curl(
        'curl -X POST https://api.example.com/login '
        '-H "Content-Type: application/json" -d \'{"u":"a"}\''
    )
    assert req.method == "POST"
    assert req.path == "/login"
    assert req.host == "api.example.com"
    assert req.headers["Content-Type"] == "application/json"
    assert req.body == '{"u":"a"}'


def test_parse_curl_infers_get_with_query():
    req = parse_curl("curl 'https://x.com/search?q=1'")
    assert req.method == "GET"
    assert req.path == "/search?q=1"
    assert req.scheme == "https"


def test_parse_curl_line_continuations():
    req = parse_curl("curl https://x.com/a \\\n  -H 'X-Test: 1'")
    assert req.headers["X-Test"] == "1"


def test_parse_curl_no_url_raises():
    with pytest.raises(ParseError):
        parse_curl("curl -X GET -H 'A: b'")


def test_parse_har_multiple_entries():
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://x.com/a?b=1", "headers": []},
                    "response": {"status": 200, "statusText": "OK", "headers": [], "content": {"text": "hi"}},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://x.com/submit",
                        "headers": [{"name": "Content-Type", "value": "text/plain"}],
                        "postData": {"text": "payload"},
                    },
                },
            ]
        }
    }
    caps = parse_har(json.dumps(har))
    assert len(caps) == 2
    assert caps[0].request.path == "/a?b=1"
    assert caps[0].response is not None and caps[0].response.status_code == 200
    assert caps[1].request.method == "POST"
    assert caps[1].request.body == "payload"
    assert caps[1].response is None


def test_parse_har_empty_raises():
    with pytest.raises(ParseError):
        parse_har(json.dumps({"log": {"entries": []}}))


def test_parse_har_invalid_json_raises():
    with pytest.raises(ParseError):
        parse_har("{not json")


def test_parse_burp_xml_base64():
    raw_req = base64.b64encode(b"GET /admin HTTP/1.1\r\nHost: t.com\r\n\r\n").decode()
    raw_resp = base64.b64encode(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nadmin panel").decode()
    xml = (
        f"<items><item><url>https://t.com/admin</url><host>t.com</host>"
        f"<protocol>https</protocol>"
        f'<request base64="true">{raw_req}</request>'
        f'<response base64="true">{raw_resp}</response></item></items>'
    )
    caps = parse_burp_xml(xml)
    assert len(caps) == 1
    assert caps[0].request.method == "GET"
    assert caps[0].request.path == "/admin"
    assert caps[0].request.scheme == "https"
    assert caps[0].response is not None and caps[0].response.status_code == 200


def test_parse_burp_xml_no_items_raises():
    with pytest.raises(ParseError):
        parse_burp_xml("<items></items>")


def test_detect_format(tmp_path: Path):
    har = tmp_path / "cap.har"
    har.write_text(json.dumps({"log": {"entries": []}}))
    assert detect_format(har) == "har"

    curl = tmp_path / "cmd.txt"
    curl.write_text("curl https://x.com/")
    assert detect_format(curl) == "curl"

    raw = tmp_path / "r.req"
    raw.write_text("GET / HTTP/1.1\nHost: x.com\n\n")
    assert detect_format(raw) == "raw"


def test_import_file_auto_raw(tmp_path: Path):
    raw = tmp_path / "r.req"
    raw.write_text("GET /x HTTP/1.1\nHost: x.com\n\n")
    caps = import_file(raw)
    assert len(caps) == 1
    assert caps[0].request.path == "/x"

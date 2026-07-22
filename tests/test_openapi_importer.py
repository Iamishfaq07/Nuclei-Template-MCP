import textwrap

import pytest

from mcp_nuclei.core.importers import detect_format, parse_openapi
from mcp_nuclei.core.parser import ParseError

OPENAPI_SPEC = textwrap.dedent(
    """
    openapi: 3.0.0
    info:
      title: Test API
      version: 1.0.0
    servers:
      - url: https://api.example.com/v1
    paths:
      /orders/{id}:
        get:
          summary: Get order
          parameters:
            - name: id
              in: path
              required: true
              schema:
                type: integer
                example: 42
            - name: X-Api-Key
              in: header
              schema:
                type: string
          responses:
            "200":
              description: ok
      /login:
        post:
          requestBody:
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    username:
                      type: string
                      example: admin
                    password:
                      type: string
    """
)

SWAGGER_SPEC = textwrap.dedent(
    """
    swagger: "2.0"
    host: legacy.example.com
    schemes: [https]
    basePath: /api
    paths:
      /widgets:
        get:
          parameters:
            - name: q
              in: query
              type: string
              example: search-term
          responses:
            200:
              description: ok
    """
)


def test_parse_openapi_get_with_path_and_header_params():
    captures = parse_openapi(OPENAPI_SPEC)
    get_capture = next(c for c in captures if c.request.method == "GET")
    assert get_capture.request.path == "/orders/42"
    assert get_capture.request.host == "api.example.com"
    assert get_capture.request.scheme == "https"
    assert "X-Api-Key" in get_capture.request.headers


def test_parse_openapi_post_builds_json_body_from_schema():
    captures = parse_openapi(OPENAPI_SPEC)
    post_capture = next(c for c in captures if c.request.method == "POST")
    assert post_capture.request.path == "/login"
    assert '"username": "admin"' in post_capture.request.body
    assert post_capture.request.headers.get("Content-Type") == "application/json"


def test_parse_openapi_swagger2_host_and_query():
    captures = parse_openapi(SWAGGER_SPEC)
    assert len(captures) == 1
    request = captures[0].request
    assert request.host == "legacy.example.com"
    assert request.path == "/api/widgets?q=search-term"


def test_parse_openapi_no_paths_raises():
    with pytest.raises(ParseError):
        parse_openapi("openapi: 3.0.0\ninfo:\n  title: x\n")


def test_parse_openapi_invalid_yaml_raises():
    with pytest.raises(ParseError):
        parse_openapi("openapi: [unterminated")


def test_detect_format_openapi_json(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text('{"openapi": "3.0.0", "paths": {}}')
    assert detect_format(spec_file) == "openapi"


def test_detect_format_openapi_yaml(tmp_path):
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(OPENAPI_SPEC)
    assert detect_format(spec_file) == "openapi"


def test_detect_format_non_openapi_yaml_falls_back_to_raw(tmp_path):
    spec_file = tmp_path / "notes.yaml"
    spec_file.write_text("just: some\nrandom: yaml\n")
    assert detect_format(spec_file) == "raw"

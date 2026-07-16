from pathlib import Path

import pytest

from mcp_nuclei.core.generator import (
    GenerationError,
    detect_vuln_type,
    generate_template,
)
from mcp_nuclei.mcp.client import CallableMCPClient

STUB_TEMPLATE = """
id: stub-template
info:
  name: Stub Template
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/orders/2001"
    matchers:
      - type: status
        status:
          - 200
"""


@pytest.fixture()
def request_file(tmp_path: Path) -> Path:
    req = tmp_path / "sample.req"
    req.write_text("GET /api/v1/orders/2001 HTTP/1.1\nHost: shop.example.com\n\n")
    return req


def test_detect_vuln_type_idor():
    assert detect_vuln_type("IDOR in the order endpoint") == "idor"


def test_detect_vuln_type_sqli():
    assert detect_vuln_type("classic SQL injection via id param") == "sqli"


def test_detect_vuln_type_none_for_unknown():
    assert detect_vuln_type("some vague description") is None


def test_detect_vuln_type_none_for_empty():
    assert detect_vuln_type(None) is None


def test_generate_template_end_to_end(request_file: Path):
    client = CallableMCPClient(lambda system, user: STUB_TEMPLATE)

    result = generate_template(
        request_path=request_file,
        client=client,
        description="IDOR in order endpoint",
    )

    assert result.detected_type == "idor"
    assert result.template_dict["id"] == "stub-template"
    assert "matchers" in result.raw_mcp_output
    assert "id: stub-template" in result.template_yaml


def test_generate_template_raises_on_empty_mcp_output(request_file: Path):
    client = CallableMCPClient(lambda system, user: "")
    with pytest.raises(GenerationError):
        generate_template(request_path=request_file, client=client)


def test_generate_template_raises_on_invalid_yaml(request_file: Path):
    client = CallableMCPClient(lambda system, user: "id: [unterminated")
    with pytest.raises(GenerationError):
        generate_template(request_path=request_file, client=client)


def test_generate_template_raises_on_missing_request_file(tmp_path: Path):
    client = CallableMCPClient(lambda system, user: STUB_TEMPLATE)
    with pytest.raises(GenerationError):
        generate_template(request_path=tmp_path / "missing.req", client=client)


def test_generate_template_forced_type_overrides_description(request_file: Path):
    client = CallableMCPClient(lambda system, user: STUB_TEMPLATE)
    result = generate_template(request_path=request_file, client=client, vuln_type="sqli")
    assert result.detected_type == "sqli"

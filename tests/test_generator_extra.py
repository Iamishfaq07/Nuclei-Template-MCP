from pathlib import Path

import pytest

from mcp_nuclei.core.generator import (
    GenerationError,
    build_prepared_prompt,
    detect_vuln_type,
    generate_from_capture,
)
from mcp_nuclei.core.importers import RequestCapture
from mcp_nuclei.core.parser import _parse_request_text
from mcp_nuclei.mcp.client import CallableMCPClient

STUB_TEMPLATE = """
id: stub
info:
  name: Stub
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
"""

IMPROVED_TEMPLATE = """
id: stub-improved
info:
  name: Stub Improved
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
"""


def _capture() -> RequestCapture:
    req = _parse_request_text("GET /x HTTP/1.1\nHost: t.com\n\n", source="test")
    return RequestCapture(request=req, label="t")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("server-side request forgery here", "ssrf"),
        ("XML external entity injection", "xxe"),
        ("path traversal in download", "lfi"),
        ("open redirect on login", "open-redirect"),
        ("template injection ssti", "ssti"),
        ("authentication bypass via header", "auth-bypass"),
        ("CORS misconfiguration", "cors"),
        ("OS command injection", "cmdi"),
    ],
)
def test_detect_new_vuln_types(text, expected):
    assert detect_vuln_type(text) == expected


def test_build_prepared_prompt_includes_specialised(tmp_path: Path):
    cap = _capture()
    prepared = build_prepared_prompt(request=cap.request, vuln_type="ssrf")
    assert prepared.detected_type == "ssrf"
    assert "SSRF" in prepared.system_prompt
    assert "GET /x" in prepared.user_prompt


def test_auto_classify_uses_mcp():
    # Model returns "sqli" for the classifier call, then the template.
    def fn(system, user):
        if "classifier" in system:
            return "sqli"
        return STUB_TEMPLATE

    client = CallableMCPClient(fn)
    result = generate_from_capture(_capture(), client=client, auto_classify=True)
    assert result.detected_type == "sqli"


def test_refine_runs_second_pass():
    def fn(system, user):
        if "reviewer" in system.lower() or "improve" in system.lower():
            return IMPROVED_TEMPLATE
        return STUB_TEMPLATE

    client = CallableMCPClient(fn)
    result = generate_from_capture(_capture(), client=client, refine=True)
    assert result.refined is True
    assert result.template_dict["id"] == "stub-improved"


def test_generate_from_capture_empty_raises():
    client = CallableMCPClient(lambda s, u: "")
    with pytest.raises(GenerationError):
        generate_from_capture(_capture(), client=client)

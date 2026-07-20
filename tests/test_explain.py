from mcp_nuclei.core.generator import GenerationError, explain_template
from mcp_nuclei.core.parser import _parse_request_text
from mcp_nuclei.mcp.client import CallableMCPClient


def test_explain_template_returns_rationale():
    req = _parse_request_text("GET /x HTTP/1.1\nHost: t.com\n\n", source="test")
    client = CallableMCPClient(lambda s, u: "  This proves the bug because X.  ")
    rationale = explain_template("id: x", req, client)
    assert rationale == "This proves the bug because X."


def test_explain_template_wraps_client_errors():
    req = _parse_request_text("GET /x HTTP/1.1\nHost: t.com\n\n", source="test")

    def boom(system_prompt, user_prompt):
        raise RuntimeError("network down")

    client = CallableMCPClient(boom)
    try:
        explain_template("id: x", req, client)
        assert False, "expected GenerationError"
    except GenerationError as exc:
        assert "network down" in str(exc)

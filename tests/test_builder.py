import pytest

from mcp_nuclei.core import builder


def test_slugify_id():
    assert builder.slugify_id("IDOR in Order Endpoint!") == "idor-in-order-endpoint"
    assert builder.slugify_id("  multiple   spaces  ") == "multiple-spaces"
    assert builder.slugify_id("") == "generated-template"


def test_extract_yaml_block_strips_fence():
    text = "```yaml\nid: foo\ninfo:\n  name: bar\n```"
    assert builder.extract_yaml_block(text) == "id: foo\ninfo:\n  name: bar"


def test_extract_yaml_block_no_fence_passthrough():
    text = "id: foo\ninfo:\n  name: bar"
    assert builder.extract_yaml_block(text) == text


def test_parse_template_yaml_invalid_yaml_raises():
    with pytest.raises(builder.BuildError):
        builder.parse_template_yaml("id: [unterminated")


def test_parse_template_yaml_non_mapping_raises():
    with pytest.raises(builder.BuildError):
        builder.parse_template_yaml("- just\n- a\n- list")


def test_normalize_template_fills_defaults():
    data = {"http": [{"method": "GET", "path": ["{{BaseURL}}/x"]}]}
    normalized = builder.normalize_template(data, fallback_name="My Vuln")

    assert normalized["id"] == "my-vuln"
    assert normalized["info"]["name"] == "My Vuln"
    assert normalized["info"]["author"] == "mcp-nuclei"
    assert normalized["info"]["severity"] == "medium"


def test_normalize_template_merges_tags():
    data = {"info": {"name": "x", "tags": "idor"}, "http": []}
    normalized = builder.normalize_template(data, fallback_name="x", tags="bac,idor")
    assert normalized["info"]["tags"] == "bac,idor"


def test_normalize_template_adds_classification():
    data = {"info": {"name": "x"}, "http": []}
    normalized = builder.normalize_template(data, fallback_name="x", cve_id="CVE-2024-12345", cwe_id="CWE-639")
    assert normalized["info"]["classification"] == {"cve-id": "cve-2024-12345", "cwe-id": "cwe-639"}


def test_normalize_template_no_classification_when_not_requested():
    data = {"info": {"name": "x"}, "http": []}
    normalized = builder.normalize_template(data, fallback_name="x")
    assert "classification" not in normalized["info"]


def test_normalize_template_preserves_existing_classification():
    data = {"info": {"name": "x", "classification": {"cve-id": "cve-2020-0001"}}, "http": []}
    normalized = builder.normalize_template(data, fallback_name="x", cwe_id="CWE-89")
    assert normalized["info"]["classification"] == {"cve-id": "cve-2020-0001", "cwe-id": "cwe-89"}


def test_normalize_template_rejects_bad_severity():
    data = {"info": {"name": "x", "severity": "extreme"}, "http": []}
    with pytest.raises(builder.BuildError):
        builder.normalize_template(data, fallback_name="x")


def test_normalize_template_converts_requests_key():
    data = {"info": {"name": "x"}, "requests": [{"method": "GET"}]}
    normalized = builder.normalize_template(data, fallback_name="x")
    assert "http" in normalized
    assert "requests" not in normalized


def test_validate_template_requires_protocol_block():
    with pytest.raises(builder.BuildError):
        builder.validate_template({"id": "x", "info": {}})


def test_validate_template_passes_with_http_block():
    builder.validate_template({"id": "x", "info": {}, "http": []})


def test_to_yaml_orders_keys():
    template = {"http": [], "id": "abc", "info": {"name": "x"}}
    rendered = builder.to_yaml(template)
    assert rendered.index("id:") < rendered.index("info:") < rendered.index("http:")

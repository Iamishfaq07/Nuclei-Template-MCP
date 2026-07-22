from mcp_nuclei.core.lint import lint_template


def _good_template():
    return {
        "id": "my-template-name",
        "info": {
            "name": "My Template",
            "author": "me",
            "severity": "medium",
            "description": "Detects a thing.",
            "tags": "idor,bac",
        },
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/x"],
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "word", "part": "body", "words": ["unique_marker_1337"]},
                ],
            }
        ],
    }


def test_lint_clean_template_has_no_issues():
    assert lint_template(_good_template()) == []


def test_lint_missing_id():
    template = _good_template()
    del template["id"]
    issues = lint_template(template)
    assert any(i.level == "error" and "id" in i.message for i in issues)


def test_lint_non_kebab_id_warns():
    template = _good_template()
    template["id"] = "My_Template_ID"
    issues = lint_template(template)
    assert any("kebab-case" in i.message for i in issues)


def test_lint_missing_name_is_error():
    template = _good_template()
    del template["info"]["name"]
    issues = lint_template(template)
    assert any(i.level == "error" and "name" in i.message for i in issues)


def test_lint_missing_tags_warns():
    template = _good_template()
    del template["info"]["tags"]
    issues = lint_template(template)
    assert any("tags" in i.message for i in issues)


def test_lint_high_severity_without_classification_warns():
    template = _good_template()
    template["info"]["severity"] = "critical"
    issues = lint_template(template)
    assert any("classification" in i.message for i in issues)


def test_lint_high_severity_with_classification_no_warning():
    template = _good_template()
    template["info"]["severity"] = "critical"
    template["info"]["classification"] = {"cve-id": "cve-2024-12345"}
    issues = lint_template(template)
    assert not any("classification" in i.message for i in issues)


def test_lint_no_matchers_flagged():
    template = _good_template()
    template["http"][0]["matchers"] = []
    issues = lint_template(template)
    assert any("no matchers" in i.message for i in issues)


def test_lint_status_only_matcher_flagged():
    template = _good_template()
    template["http"][0]["matchers"] = [{"type": "status", "status": [200]}]
    issues = lint_template(template)
    assert any("only on status code" in i.message for i in issues)


def test_lint_generic_word_matcher_flagged():
    template = _good_template()
    template["http"][0]["matchers"] = [
        {"type": "status", "status": [200]},
        {"type": "word", "part": "body", "words": ["success"]},
    ]
    issues = lint_template(template)
    assert any("generic" in i.message for i in issues)


def test_lint_hardcoded_host_flagged():
    template = _good_template()
    template["http"][0]["path"] = ["https://vulnerable-shop.example.com/x"]
    issues = lint_template(template)
    assert any("hardcoded host" in i.message for i in issues)


def test_lint_variable_host_not_flagged():
    template = _good_template()
    template["http"][0]["path"] = ["{{BaseURL}}/x"]
    issues = lint_template(template)
    assert not any("hardcoded host" in i.message for i in issues)

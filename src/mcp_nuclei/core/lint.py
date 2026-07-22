"""Style/convention linting for Nuclei templates.

This is deliberately separate from `core/validator.py` (which only checks
that `nuclei` can parse the YAML) and `core/verify.py` (which checks live
behavior). `lint` instead checks the *conventions* the official
`nuclei-templates` repository expects: id format, presence of metadata,
and a few common false-positive smells — the kind of thing a human
reviewer would flag in a PR.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_HARDCODED_HOST_RE = re.compile(
    r"(https?://)(?!\{\{)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)
_GENERIC_WORDS = {"error", "success", "ok", "true", "false", "welcome", "home"}


@dataclass
class LintIssue:
    """A single lint finding."""

    level: str  # "error" | "warning"
    message: str


def lint_template(template: dict[str, Any]) -> list[LintIssue]:
    """Check a parsed template dict against nuclei-templates conventions."""
    issues: list[LintIssue] = []

    template_id = template.get("id")
    if not template_id:
        issues.append(LintIssue("error", "Missing 'id'."))
    elif not _ID_RE.match(str(template_id)):
        issues.append(
            LintIssue("warning", f"id {template_id!r} is not lowercase kebab-case (e.g. 'my-template-name').")
        )

    info = template.get("info") or {}
    if not info.get("name"):
        issues.append(LintIssue("error", "info.name is missing."))
    if not info.get("author"):
        issues.append(LintIssue("warning", "info.author is missing."))
    if not info.get("description"):
        issues.append(LintIssue("warning", "info.description is missing — reviewers expect a one-line summary."))
    if not info.get("tags"):
        issues.append(LintIssue("warning", "info.tags is missing — templates should be discoverable by tag."))

    severity = str(info.get("severity", "")).lower()
    if severity in {"high", "critical"} and not info.get("classification"):
        issues.append(
            LintIssue(
                "warning",
                f"severity is {severity!r} but info.classification (cve-id/cwe-id/cvss) is not set. "
                "Consider adding it if this maps to a known CVE/CWE.",
            )
        )

    issues.extend(_lint_matchers(template))
    issues.extend(_lint_hardcoded_hosts(template))

    return issues


def _walk_blocks(template: dict[str, Any]) -> list[Any]:
    blocks: list[Any] = []
    for key in ("http", "network", "dns", "file", "headless", "ssl", "websocket"):
        value = template.get(key)
        if isinstance(value, list):
            blocks.extend(value)
    return blocks


def _lint_matchers(template: dict[str, Any]) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for block in _walk_blocks(template):
        if not isinstance(block, dict):
            continue
        matchers = block.get("matchers")
        if not matchers:
            issues.append(LintIssue("warning", "A request block has no matchers — it can never report a finding."))
            continue
        if not isinstance(matchers, list):
            continue

        status_only = len(matchers) == 1 and matchers[0].get("type") == "status"
        if status_only:
            issues.append(
                LintIssue(
                    "warning",
                    "A request block matches only on status code — this is prone to false positives. "
                    "Consider combining with a word/regex matcher on distinctive content.",
                )
            )

        for matcher in matchers:
            if not isinstance(matcher, dict) or matcher.get("type") != "word":
                continue
            words = [str(w).lower() for w in matcher.get("words", [])]
            generic = [w for w in words if w in _GENERIC_WORDS]
            if generic:
                issues.append(
                    LintIssue(
                        "warning",
                        f"Matcher word(s) {generic} are generic and likely to appear on unrelated pages.",
                    )
                )
    return issues


def _lint_hardcoded_hosts(template: dict[str, Any]) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for block in _walk_blocks(template):
        if not isinstance(block, dict):
            continue
        for field_name in ("path", "raw"):
            value = block.get(field_name)
            values = value if isinstance(value, list) else [value] if value else []
            for entry in values:
                if isinstance(entry, str) and _HARDCODED_HOST_RE.search(entry):
                    issues.append(
                        LintIssue(
                            "warning",
                            f"Found what looks like a hardcoded host in {field_name!r} — "
                            "prefer {{BaseURL}}/{{Hostname}} so the template works against any target.",
                        )
                    )
                    break
    return issues

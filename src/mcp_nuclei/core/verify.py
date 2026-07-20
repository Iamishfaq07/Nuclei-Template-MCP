"""Live verification: run a generated template against a real target.

Rather than reimplementing Nuclei's HTTP engine and matcher/extractor
evaluation logic (a large and error-prone undertaking), this shells out to
the real `nuclei` binary and asks it to actually run the template against a
target URL. This is the most reliable way to confirm the generated
matchers/extractors behave as intended on a live target — closing the gap
between "the YAML is well-formed" (`core/validator.py`) and "the template
actually detects the vulnerability".

This is opt-in and only ever runs against a URL the caller explicitly
supplies (`--verify-url`); nothing here fires requests on its own.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mcp_nuclei.core.validator import nuclei_path


@dataclass
class VerifyResult:
    """Outcome of running a template against a live target via `nuclei`."""

    ran: bool
    matched: bool
    available: bool
    matches: list[dict] = field(default_factory=list)
    raw_output: str = ""
    detail: str = ""


def verify_yaml(
    template_yaml: str,
    target_url: str,
    *,
    timeout: int = 30,
    extra_args: Optional[str] = None,
) -> VerifyResult:
    """Run `nuclei -t <template> -u <target_url> -jsonl -silent` and report matches.

    `extra_args` (shell-quoted string) lets callers pass through additional
    nuclei flags (e.g. `-rate-limit 1`) without this module needing to know
    about every possible option.
    """
    binary = nuclei_path()
    if binary is None:
        return VerifyResult(
            ran=False,
            matched=False,
            available=False,
            detail="The 'nuclei' binary was not found on PATH. Install it from "
            "https://github.com/projectdiscovery/nuclei to enable live verification.",
        )

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(template_yaml)
        tmp_path = Path(tmp.name)

    cmd = [binary, "-t", str(tmp_path), "-u", target_url, "-jsonl", "-silent", "-no-color"]
    if extra_args:
        cmd += shlex.split(extra_args)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        tmp_path.unlink(missing_ok=True)
        return VerifyResult(True, False, True, detail=f"nuclei run timed out after {timeout}s")
    except OSError as exc:  # pragma: no cover - defensive
        tmp_path.unlink(missing_ok=True)
        return VerifyResult(True, False, True, detail=f"Failed to run nuclei: {exc}")
    finally:
        tmp_path.unlink(missing_ok=True)

    raw = (proc.stdout or "").strip()
    matches: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            matches.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    detail = (proc.stderr or "").strip()
    return VerifyResult(
        ran=True,
        matched=len(matches) > 0,
        available=True,
        matches=matches,
        raw_output=raw,
        detail=detail,
    )

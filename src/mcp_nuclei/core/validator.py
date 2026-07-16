"""Validate generated templates against the real `nuclei` binary.

If the `nuclei` CLI is installed and on PATH, we can run
`nuclei -validate -t <file>` to confirm the template actually parses and
lints in Nuclei itself — closing the gap between "looks valid" and "is
valid". When the binary isn't available, callers get a clear, non-fatal
signal so generation still works without it.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ValidationResult:
    """Outcome of a `nuclei -validate` run."""

    ok: bool
    available: bool
    output: str
    detail: str = ""


def nuclei_path() -> Optional[str]:
    """Return the path to the `nuclei` binary if installed, else None."""
    return shutil.which("nuclei")


def is_available() -> bool:
    """True if the `nuclei` binary is installed and on PATH."""
    return nuclei_path() is not None


def validate_file(path: Path, timeout: int = 60) -> ValidationResult:
    """Run `nuclei -validate -t <path>` and capture the result."""
    binary = nuclei_path()
    if binary is None:
        return ValidationResult(
            ok=False,
            available=False,
            output="",
            detail="The 'nuclei' binary was not found on PATH. Install it from "
            "https://github.com/projectdiscovery/nuclei to enable validation.",
        )

    try:
        proc = subprocess.run(
            [binary, "-validate", "-t", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(False, True, "", detail=f"nuclei validation timed out after {timeout}s")
    except OSError as exc:  # pragma: no cover - defensive
        return ValidationResult(False, True, "", detail=f"Failed to run nuclei: {exc}")

    combined = (proc.stdout + proc.stderr).strip()
    return ValidationResult(ok=proc.returncode == 0, available=True, output=combined)


def validate_yaml(template_yaml: str, timeout: int = 60) -> ValidationResult:
    """Validate a template given as a YAML string by writing it to a temp file."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(template_yaml)
        tmp_path = Path(tmp.name)
    try:
        return validate_file(tmp_path, timeout=timeout)
    finally:
        tmp_path.unlink(missing_ok=True)

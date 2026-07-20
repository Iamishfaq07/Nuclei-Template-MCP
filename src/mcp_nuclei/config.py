"""Configuration loading for mcp-nuclei.

Defaults (author, severity, tags, backend, model) can be set in a TOML
config file so they don't have to be passed on every invocation. Lookup
order (first found wins):

1. `--config PATH` (handled by the CLI, passed explicitly to `load_config`)
2. `./.mcp-nuclei.toml` in the current working directory
3. `~/.config/mcp-nuclei/config.toml`
4. `~/.mcp-nuclei.toml`

CLI flags always override config-file values, which override built-in
defaults.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:  # Python 3.11+ ships tomllib in the stdlib.
    import tomllib
except ModuleNotFoundError:  # Python 3.10: fall back to the tomli backport.
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Config:
    """Resolved configuration defaults."""

    author: str = "mcp-nuclei"
    severity: str = "medium"
    tags: Optional[str] = None
    backend: str = "anthropic"
    model: Optional[str] = None
    refine: bool = False
    auto_classify: bool = False


class ConfigError(Exception):
    """Raised when a config file exists but cannot be read/parsed."""


def _candidate_paths() -> list[Path]:
    return [
        Path.cwd() / ".mcp-nuclei.toml",
        Path.home() / ".config" / "mcp-nuclei" / "config.toml",
        Path.home() / ".mcp-nuclei.toml",
    ]


def find_config_file(explicit: Optional[Path] = None) -> Optional[Path]:
    """Return the first existing config file, or None."""
    if explicit is not None:
        if not explicit.exists():
            raise ConfigError(f"Config file not found: {explicit}")
        return explicit
    for candidate in _candidate_paths():
        if candidate.exists():
            return candidate
    return None


def load_config(explicit: Optional[Path] = None) -> Config:
    """Load configuration defaults from the first available config file."""
    path = find_config_file(explicit)
    if path is None:
        return Config()

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Could not parse config file {path}: {exc}") from exc

    # Allow either a flat table or a [mcp-nuclei] / [tool.mcp-nuclei] section.
    section = data.get("mcp-nuclei") or data.get("tool", {}).get("mcp-nuclei") or data
    defaults = Config()
    return Config(
        author=section.get("author", defaults.author),
        severity=section.get("severity", defaults.severity),
        tags=section.get("tags", defaults.tags),
        backend=section.get("backend", defaults.backend),
        model=section.get("model", defaults.model),
        refine=bool(section.get("refine", defaults.refine)),
        auto_classify=bool(section.get("auto_classify", defaults.auto_classify)),
    )


def resolve_model(config: Config) -> Optional[str]:
    """Resolve the model, letting the MCP_NUCLEI_MODEL env var win over config."""
    return os.environ.get("MCP_NUCLEI_MODEL") or config.model

"""Opt-in on-disk caching for MCP responses.

Generation prompts are deterministic given the same request/response/
description, so re-running `generate` while tuning a description or CLI
flags often re-sends an identical prompt. `CachingMCPClient` wraps any
`MCPClient` and skips the API call (and its cost) when an identical
system/user prompt pair for the same model was already answered.

Caching is opt-in (`--cache` on the CLI) because a cached answer can go
stale relative to prompt/model changes made outside the hashed key (e.g. a
different backend version) — callers who want a guaranteed-fresh response
should leave it off.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

from mcp_nuclei.mcp.client import MCPClient


def default_cache_dir() -> Path:
    """Return the default cache directory, honoring XDG_CACHE_HOME."""
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "mcp-nuclei" / "responses"


def _cache_key(system_prompt: str, user_prompt: str, tag: str) -> str:
    digest = hashlib.sha256()
    digest.update(tag.encode("utf-8"))
    digest.update(b"\0")
    digest.update(system_prompt.encode("utf-8"))
    digest.update(b"\0")
    digest.update(user_prompt.encode("utf-8"))
    return digest.hexdigest()


class CachingMCPClient:
    """Wraps an `MCPClient`, caching responses on disk keyed by prompt hash."""

    def __init__(self, inner: MCPClient, cache_dir: Optional[Path] = None, tag: str = "default") -> None:
        self._inner = inner
        self._dir = cache_dir or default_cache_dir()
        self._tag = tag
        self.last_hit: bool = False

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        key = _cache_key(system_prompt, user_prompt, self._tag)
        path = self._dir / f"{key}.txt"

        if path.exists():
            self.last_hit = True
            return path.read_text(encoding="utf-8")

        self.last_hit = False
        result = self._inner.generate(system_prompt=system_prompt, user_prompt=user_prompt)

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            path.write_text(result, encoding="utf-8")
        except OSError:
            pass  # Caching is best-effort; a write failure shouldn't break generation.

        return result

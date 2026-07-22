"""Opt-in retry with exponential backoff for MCP calls.

Backend API calls can fail transiently (rate limits, brief network blips).
`RetryingMCPClient` wraps any `MCPClient` and retries a failed `generate()`
call with exponential backoff before giving up. It is opt-in (`--retries`)
rather than a silent default, so a persistent failure still surfaces
promptly instead of retrying for a long time unexpectedly.
"""
from __future__ import annotations

import random
import time

from mcp_nuclei.mcp.client import MCPClient


class RetryingMCPClient:
    """Wraps an `MCPClient`, retrying `generate()` with exponential backoff on failure."""

    def __init__(
        self,
        inner: MCPClient,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
    ) -> None:
        self._inner = inner
        self._max_retries = max(0, max_retries)
        self._base_delay = base_delay
        self._max_delay = max_delay
        self.attempts: int = 0

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        last_exc: Exception = RuntimeError("no attempts were made")
        for attempt in range(self._max_retries + 1):
            self.attempts = attempt + 1
            try:
                return self._inner.generate(system_prompt=system_prompt, user_prompt=user_prompt)
            except Exception as exc:  # noqa: BLE001 - deliberately broad: any backend failure is retryable
                last_exc = exc
                if attempt >= self._max_retries:
                    break
                delay = min(self._max_delay, self._base_delay * (2**attempt))
                delay += random.uniform(0, delay * 0.1)  # jitter
                time.sleep(delay)
        raise last_exc

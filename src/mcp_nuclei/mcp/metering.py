"""Accumulate token usage/cost across multiple `generate()` calls.

A single backend client (`AnthropicMCPClient`, `OpenAIMCPClient`) only
exposes the *most recent* call's usage via `.last_usage`. That's not
enough for `--cost`, since a single CLI invocation often makes several
calls under the hood (`--refine` is generate + critique, `--auto-classify`
adds a classification call, `batch` makes many). `MeteringMCPClient` wraps
any `MCPClient` and sums usage/estimated cost across every call routed
through it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from mcp_nuclei.mcp.client import MCPClient, Usage
from mcp_nuclei.mcp.pricing import estimate_cost_usd


@dataclass
class UsageTotals:
    """Running totals accumulated by a `MeteringMCPClient`."""

    call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    priced_calls: int = 0

    @property
    def has_cost_estimate(self) -> bool:
        return self.priced_calls > 0


class MeteringMCPClient:
    """Wraps an `MCPClient`, accumulating usage/cost across all calls made through it."""

    def __init__(self, inner: MCPClient) -> None:
        self._inner = inner
        self.totals = UsageTotals()

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        result = self._inner.generate(system_prompt=system_prompt, user_prompt=user_prompt)

        usage: Optional[Usage] = getattr(self._inner, "last_usage", None)
        if usage is not None:
            self.totals.call_count += 1
            self.totals.input_tokens += usage.input_tokens
            self.totals.output_tokens += usage.output_tokens
            cost = estimate_cost_usd(usage)
            if cost is not None:
                self.totals.estimated_cost_usd += cost
                self.totals.priced_calls += 1

        return result

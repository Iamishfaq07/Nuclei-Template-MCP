"""Rough cost estimation from token usage.

Prices are approximate, USD per 1M tokens, and will drift out of date —
this is meant to give a ballpark ("this batch run cost about $0.40"), not
an exact bill. Unknown models simply produce no estimate.
"""
from __future__ import annotations

from typing import Optional

from mcp_nuclei.mcp.client import Usage

# (input $/1M tokens, output $/1M tokens), keyed by a substring match
# against the model name so minor version suffixes still resolve.
_PRICE_TABLE: dict[str, tuple[float, float]] = {
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1": (2.0, 8.0),
}


def estimate_cost_usd(usage: Usage) -> Optional[float]:
    """Estimate USD cost for a `Usage` record, or None if the model is unrecognized."""
    model = usage.model.lower()
    for key, (input_price, output_price) in _PRICE_TABLE.items():
        if key in model:
            return (usage.input_tokens / 1_000_000) * input_price + (
                usage.output_tokens / 1_000_000
            ) * output_price
    return None

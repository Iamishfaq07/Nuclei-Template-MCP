"""MCP integration point.

Everything else in `mcp-nuclei` depends only on the `MCPClient` protocol
defined here, not on any particular agent framework or LLM provider.
Wiring in a different backend — a locally running MCP server, a different
model provider, an existing agent session object you already have — only
requires implementing `generate()`.

A concrete `AnthropicMCPClient` is included so the CLI works out of the box
if you have an `ANTHROPIC_API_KEY` set, but it is just one possible backend.
"""
from __future__ import annotations

import os
from typing import Callable, Optional, Protocol, runtime_checkable


class MCPClientError(Exception):
    """Raised when the configured MCP client cannot produce a response."""


@runtime_checkable
class MCPClient(Protocol):
    """Minimal interface required from any MCP/LLM backend."""

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        """Return the raw text response for a system/user prompt pair.

        Implementations should return the model's text output as-is; any
        cleanup (stripping markdown fences, YAML parsing, validation) is
        handled downstream by `mcp_nuclei.core.builder`.
        """
        ...


class CallableMCPClient:
    """Adapt an arbitrary callable to the `MCPClient` interface.

    Handy for tests, or for plugging in an MCP agent/session object you
    already have set up elsewhere:

        client = CallableMCPClient(lambda system, user: my_agent.ask(system, user))
    """

    def __init__(self, fn: Callable[[str, str], str]) -> None:
        self._fn = fn

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        return self._fn(system_prompt, user_prompt)


class AnthropicMCPClient:
    """`MCPClient` backed directly by the Anthropic Claude API.

    Requires the optional `anthropic` dependency (`pip install mcp-nuclei[llm]`)
    and an `ANTHROPIC_API_KEY` environment variable (or an explicit `api_key`).
    """

    def __init__(
        self,
        model: str = "claude-sonnet-5",
        max_tokens: int = 4096,
        api_key: Optional[str] = None,
    ) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise MCPClientError(
                "The 'anthropic' package is required for AnthropicMCPClient. "
                "Install it with: pip install mcp-nuclei[llm]"
            ) from exc

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._max_tokens = max_tokens

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as exc:
            raise MCPClientError(f"Anthropic API request failed: {exc}") from exc

        text_parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        return "\n".join(text_parts).strip()


def get_default_client() -> MCPClient:
    """Resolve the default `MCPClient` from the current environment.

    Today this resolves to `AnthropicMCPClient` when `ANTHROPIC_API_KEY` is
    set, since that's the simplest way to run mcp-nuclei end to end. Callers
    that already have their own MCP agent/session should construct and pass
    an `MCPClient` implementation directly instead of relying on this.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicMCPClient(model=os.environ.get("MCP_NUCLEI_MODEL", "claude-sonnet-5"))

    raise MCPClientError(
        "No MCP client is configured. Set ANTHROPIC_API_KEY to use the built-in "
        "Anthropic backend, or pass a custom MCPClient implementation "
        "programmatically (see mcp_nuclei.mcp.client.MCPClient)."
    )

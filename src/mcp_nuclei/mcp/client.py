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
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, runtime_checkable


class MCPClientError(Exception):
    """Raised when the configured MCP client cannot produce a response."""


@dataclass
class Usage:
    """Token usage for the most recent `generate()` call, when available."""

    model: str
    input_tokens: int
    output_tokens: int


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
        self.last_usage: Optional[Usage] = None

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

        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = Usage(
                model=self._model,
                input_tokens=getattr(usage, "input_tokens", 0),
                output_tokens=getattr(usage, "output_tokens", 0),
            )

        text_parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        return "\n".join(text_parts).strip()


class OpenAIMCPClient:
    """`MCPClient` backed by an OpenAI-compatible chat completions API.

    Works with the official OpenAI API and any OpenAI-compatible endpoint
    (including local servers like Ollama's `/v1` or LM Studio) via the
    `OPENAI_BASE_URL` env var. Requires the optional `openai` dependency
    (`pip install mcp-nuclei[openai]`) and an `OPENAI_API_KEY`.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        max_tokens: int = 4096,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        try:
            import openai
        except ImportError as exc:
            raise MCPClientError(
                "The 'openai' package is required for OpenAIMCPClient. "
                "Install it with: pip install mcp-nuclei[openai]"
            ) from exc

        self._client = openai.OpenAI(api_key=api_key, base_url=base_url or os.environ.get("OPENAI_BASE_URL"))
        self._model = model
        self._max_tokens = max_tokens
        self.last_usage: Optional[Usage] = None

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                max_tokens=self._max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
        except Exception as exc:
            raise MCPClientError(f"OpenAI API request failed: {exc}") from exc

        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = Usage(
                model=self._model,
                input_tokens=getattr(usage, "prompt_tokens", 0),
                output_tokens=getattr(usage, "completion_tokens", 0),
            )

        return (response.choices[0].message.content or "").strip()


# Default model per backend, used when none is configured explicitly.
_DEFAULT_MODELS = {"anthropic": "claude-sonnet-5", "openai": "gpt-4o"}


def get_client(backend: str = "auto", model: Optional[str] = None) -> MCPClient:
    """Resolve an `MCPClient` for the requested backend.

    `backend` may be `"anthropic"`, `"openai"`, or `"auto"` (pick whichever
    API key is present in the environment). Callers that already have their
    own MCP agent/session should construct and pass an `MCPClient`
    implementation directly instead of relying on this.
    """
    resolved = backend
    if backend == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            resolved = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            resolved = "openai"
        else:
            raise MCPClientError(
                "No MCP client is configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY "
                "(or pass --backend and the matching key), or supply a custom MCPClient "
                "implementation programmatically (see mcp_nuclei.mcp.client.MCPClient)."
            )

    chosen_model = model or os.environ.get("MCP_NUCLEI_MODEL") or _DEFAULT_MODELS.get(resolved)
    if resolved == "anthropic":
        return AnthropicMCPClient(model=chosen_model or _DEFAULT_MODELS["anthropic"])
    if resolved == "openai":
        return OpenAIMCPClient(model=chosen_model or _DEFAULT_MODELS["openai"])

    raise MCPClientError(f"Unknown backend {backend!r}; expected 'anthropic', 'openai', or 'auto'")


def get_default_client() -> MCPClient:
    """Backwards-compatible shim resolving the default client (auto backend)."""
    return get_client("auto")

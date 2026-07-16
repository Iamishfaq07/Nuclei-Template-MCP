import pytest

from mcp_nuclei.mcp.client import (
    CallableMCPClient,
    MCPClient,
    MCPClientError,
    get_client,
)


def test_callable_client_conforms_to_protocol():
    client = CallableMCPClient(lambda s, u: "ok")
    assert isinstance(client, MCPClient)
    assert client.generate(system_prompt="s", user_prompt="u") == "ok"


def test_get_client_auto_no_keys_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(MCPClientError):
        get_client("auto")


def test_get_client_unknown_backend_raises(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    with pytest.raises(MCPClientError):
        get_client("mystery")


def test_get_client_auto_prefers_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # Construction may fail if 'anthropic' isn't installed; we only assert
    # the backend selection path, so tolerate the import-time error.
    try:
        client = get_client("auto")
        assert client is not None
    except MCPClientError as exc:
        assert "anthropic" in str(exc).lower()

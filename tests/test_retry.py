import pytest

from mcp_nuclei.mcp.retry import RetryingMCPClient


def test_retry_succeeds_after_transient_failures(monkeypatch):
    calls = {"n": 0}

    def fn(system, user):
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("transient")
        return "ok"

    class _Client:
        def generate(self, *, system_prompt, user_prompt):
            return fn(system_prompt, user_prompt)

    monkeypatch.setattr("mcp_nuclei.mcp.retry.time.sleep", lambda _: None)
    client = RetryingMCPClient(_Client(), max_retries=3, base_delay=0.01)
    result = client.generate(system_prompt="s", user_prompt="u")
    assert result == "ok"
    assert calls["n"] == 3
    assert client.attempts == 3


def test_retry_raises_after_exhausting_attempts(monkeypatch):
    class _AlwaysFails:
        def generate(self, *, system_prompt, user_prompt):
            raise RuntimeError("persistent failure")

    monkeypatch.setattr("mcp_nuclei.mcp.retry.time.sleep", lambda _: None)
    client = RetryingMCPClient(_AlwaysFails(), max_retries=2, base_delay=0.01)
    with pytest.raises(RuntimeError, match="persistent failure"):
        client.generate(system_prompt="s", user_prompt="u")
    assert client.attempts == 3  # initial attempt + 2 retries


def test_retry_zero_retries_fails_immediately(monkeypatch):
    calls = {"n": 0}

    class _AlwaysFails:
        def generate(self, *, system_prompt, user_prompt):
            calls["n"] += 1
            raise RuntimeError("boom")

    client = RetryingMCPClient(_AlwaysFails(), max_retries=0)
    with pytest.raises(RuntimeError):
        client.generate(system_prompt="s", user_prompt="u")
    assert calls["n"] == 1


def test_retry_success_on_first_attempt_no_sleep(monkeypatch):
    sleep_calls = []
    monkeypatch.setattr("mcp_nuclei.mcp.retry.time.sleep", lambda d: sleep_calls.append(d))

    class _Client:
        def generate(self, *, system_prompt, user_prompt):
            return "ok"

    client = RetryingMCPClient(_Client(), max_retries=3)
    assert client.generate(system_prompt="s", user_prompt="u") == "ok"
    assert sleep_calls == []

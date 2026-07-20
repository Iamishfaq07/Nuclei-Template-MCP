from pathlib import Path

from mcp_nuclei.mcp.cache import CachingMCPClient, default_cache_dir
from mcp_nuclei.mcp.client import CallableMCPClient, Usage
from mcp_nuclei.mcp.metering import MeteringMCPClient
from mcp_nuclei.mcp.pricing import estimate_cost_usd


def test_caching_client_hits_cache_on_second_call(tmp_path: Path):
    calls = {"n": 0}

    def fn(system, user):
        calls["n"] += 1
        return f"response-{calls['n']}"

    inner = CallableMCPClient(fn)
    client = CachingMCPClient(inner, cache_dir=tmp_path)

    first = client.generate(system_prompt="s", user_prompt="u")
    assert client.last_hit is False
    second = client.generate(system_prompt="s", user_prompt="u")
    assert client.last_hit is True

    assert first == second
    assert calls["n"] == 1  # second call was served from cache, not the inner client


def test_caching_client_different_prompts_miss(tmp_path: Path):
    calls = {"n": 0}

    def fn(system, user):
        calls["n"] += 1
        return f"response-{calls['n']}"

    client = CachingMCPClient(CallableMCPClient(fn), cache_dir=tmp_path)
    client.generate(system_prompt="s", user_prompt="u1")
    client.generate(system_prompt="s", user_prompt="u2")
    assert calls["n"] == 2


def test_default_cache_dir_uses_xdg(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_dir() == tmp_path / "mcp-nuclei" / "responses"


class _UsageStubClient:
    def __init__(self, usages):
        self._usages = list(usages)
        self.last_usage = None

    def generate(self, *, system_prompt, user_prompt):
        self.last_usage = self._usages.pop(0)
        return "ok"


def test_metering_client_accumulates_usage():
    stub = _UsageStubClient(
        [
            Usage(model="claude-sonnet-5", input_tokens=100, output_tokens=50),
            Usage(model="claude-sonnet-5", input_tokens=200, output_tokens=80),
        ]
    )
    client = MeteringMCPClient(stub)
    client.generate(system_prompt="s", user_prompt="u")
    client.generate(system_prompt="s", user_prompt="u")

    assert client.totals.call_count == 2
    assert client.totals.input_tokens == 300
    assert client.totals.output_tokens == 130
    assert client.totals.has_cost_estimate is True
    assert client.totals.estimated_cost_usd > 0


def test_metering_client_no_usage_available():
    client = MeteringMCPClient(CallableMCPClient(lambda s, u: "ok"))
    client.generate(system_prompt="s", user_prompt="u")
    assert client.totals.call_count == 0


def test_estimate_cost_known_model():
    usage = Usage(model="claude-sonnet-5-20260101", input_tokens=1_000_000, output_tokens=1_000_000)
    cost = estimate_cost_usd(usage)
    assert cost == 3.0 + 15.0


def test_estimate_cost_unknown_model():
    usage = Usage(model="some-unknown-model", input_tokens=1000, output_tokens=1000)
    assert estimate_cost_usd(usage) is None

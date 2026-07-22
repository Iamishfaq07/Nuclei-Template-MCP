from pathlib import Path

from mcp_nuclei.core.plugins import PromptPlugin, load_plugin_prompts


class _FakeEntryPoint:
    def __init__(self, loader):
        self._loader = loader

    def load(self):
        return self._loader


def test_load_plugin_prompts_from_callable(monkeypatch, tmp_path: Path):
    prompt_file = tmp_path / "graphql.txt"
    prompt_file.write_text("GraphQL injection guidance")

    def get_prompts():
        return [PromptPlugin(vuln_type="graphql", prompt_path=prompt_file, keywords=("graphql",))]

    monkeypatch.setattr(
        "mcp_nuclei.core.plugins.entry_points", lambda group: [_FakeEntryPoint(get_prompts)]
    )

    plugins = load_plugin_prompts()
    assert len(plugins) == 1
    assert plugins[0].vuln_type == "graphql"
    assert plugins[0].prompt_path == prompt_file


def test_load_plugin_prompts_direct_list(monkeypatch, tmp_path: Path):
    prompt_file = tmp_path / "x.txt"
    prompt_file.write_text("x")
    direct_list = [PromptPlugin(vuln_type="x", prompt_path=prompt_file)]

    monkeypatch.setattr(
        "mcp_nuclei.core.plugins.entry_points", lambda group: [_FakeEntryPoint(direct_list)]
    )
    plugins = load_plugin_prompts()
    assert len(plugins) == 1


def test_load_plugin_prompts_single_plugin_not_list(monkeypatch, tmp_path: Path):
    prompt_file = tmp_path / "x.txt"
    prompt_file.write_text("x")
    single = PromptPlugin(vuln_type="x", prompt_path=prompt_file)

    monkeypatch.setattr(
        "mcp_nuclei.core.plugins.entry_points", lambda group: [_FakeEntryPoint(lambda: single)]
    )
    plugins = load_plugin_prompts()
    assert len(plugins) == 1


def test_load_plugin_prompts_skips_missing_prompt_file(monkeypatch, tmp_path: Path):
    missing = tmp_path / "missing.txt"

    def get_prompts():
        return [PromptPlugin(vuln_type="x", prompt_path=missing)]

    monkeypatch.setattr(
        "mcp_nuclei.core.plugins.entry_points", lambda group: [_FakeEntryPoint(get_prompts)]
    )
    assert load_plugin_prompts() == []


def test_load_plugin_prompts_broken_plugin_is_skipped(monkeypatch):
    def broken_loader():
        raise RuntimeError("plugin exploded")

    monkeypatch.setattr(
        "mcp_nuclei.core.plugins.entry_points", lambda group: [_FakeEntryPoint(broken_loader)]
    )
    assert load_plugin_prompts() == []


def test_load_plugin_prompts_no_entry_points_group(monkeypatch):
    def raise_error(group):
        raise RuntimeError("no such group")

    monkeypatch.setattr("mcp_nuclei.core.plugins.entry_points", raise_error)
    assert load_plugin_prompts() == []

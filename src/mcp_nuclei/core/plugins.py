"""Plugin system for additional vulnerability-type prompts.

Third-party packages can register extra vuln-type prompts (a new prompt
file + auto-detection keywords) without editing this repository, by
exposing a zero-argument callable under the `mcp_nuclei.vuln_prompts`
entry-point group that returns a list of `PromptPlugin`:

    # in the plugin package's pyproject.toml:
    # [project.entry-points."mcp_nuclei.vuln_prompts"]
    # my_plugin = "my_package.prompts:get_prompts"

    # in my_package/prompts.py:
    from pathlib import Path
    from mcp_nuclei.core.plugins import PromptPlugin

    def get_prompts() -> list[PromptPlugin]:
        return [
            PromptPlugin(
                vuln_type="graphql-injection",
                prompt_path=Path(__file__).parent / "graphql_injection.txt",
                keywords=("graphql injection", "graphql"),
            )
        ]

A broken or misbehaving plugin is skipped rather than crashing the CLI —
this is best-effort discovery, not a required extension point.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

ENTRY_POINT_GROUP = "mcp_nuclei.vuln_prompts"


@dataclass(frozen=True)
class PromptPlugin:
    """A vuln type contributed by a plugin: a prompt file plus detection keywords."""

    vuln_type: str
    prompt_path: Path
    keywords: tuple[str, ...] = ()


def load_plugin_prompts() -> list[PromptPlugin]:
    """Discover and load `PromptPlugin`s registered under `ENTRY_POINT_GROUP`."""
    plugins: list[PromptPlugin] = []
    try:
        discovered = entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        return plugins

    for ep in discovered:
        try:
            loaded = ep.load()
            candidates = loaded() if callable(loaded) else loaded
            if isinstance(candidates, PromptPlugin):
                candidates = [candidates]
            for item in candidates:
                if isinstance(item, PromptPlugin) and item.prompt_path.exists():
                    plugins.append(item)
        except Exception:
            continue  # A broken plugin should not break the whole CLI.

    return plugins

from pathlib import Path

import pytest

from mcp_nuclei.config import Config, ConfigError, load_config, resolve_model


def test_load_config_defaults_when_missing(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    cfg = load_config()
    assert cfg == Config()


def test_load_config_flat_table(tmp_path: Path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('author = "ish"\nseverity = "high"\ntags = "a,b"\nrefine = true\n')
    cfg = load_config(cfg_file)
    assert cfg.author == "ish"
    assert cfg.severity == "high"
    assert cfg.tags == "a,b"
    assert cfg.refine is True


def test_load_config_section(tmp_path: Path):
    cfg_file = tmp_path / "cfg.toml"
    cfg_file.write_text('[mcp-nuclei]\nbackend = "openai"\nmodel = "gpt-4o"\n')
    cfg = load_config(cfg_file)
    assert cfg.backend == "openai"
    assert cfg.model == "gpt-4o"


def test_load_config_missing_explicit_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_resolve_model_env_wins(monkeypatch):
    monkeypatch.setenv("MCP_NUCLEI_MODEL", "env-model")
    assert resolve_model(Config(model="cfg-model")) == "env-model"


def test_resolve_model_config_fallback(monkeypatch):
    monkeypatch.delenv("MCP_NUCLEI_MODEL", raising=False)
    assert resolve_model(Config(model="cfg-model")) == "cfg-model"

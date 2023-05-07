import logging
from pathlib import Path

import pytest

import secrets_env.config as t
from secrets_env.provider import ProviderBase


class TestLoadConfig:
    def test_auto_find(self, fixture_dir: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.chdir(fixture_dir)

        cfg = t.load_config()
        self.assert_config_format(cfg)

    @pytest.mark.parametrize(
        "filename",
        [
            ".secrets-env.json",
            ".secrets-env.toml",
            ".secrets-env.yaml",
            "pyproject.toml",
        ],
    )
    def test_assigned_file(self, fixture_dir: Path, filename: str):
        cfg = t.load_config(fixture_dir / filename)
        self.assert_config_format(cfg)

    def assert_config_format(self, cfg: dict):
        assert isinstance(cfg, dict)

        for name, provider in cfg["providers"].items():
            assert isinstance(name, str)
            assert isinstance(provider, ProviderBase)

        for request in cfg["requests"]:
            assert isinstance(request["name"], str)
            assert isinstance(request["provider"], str)
            assert isinstance(request["spec"], (str, dict))

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "find_config_file", lambda: None)
        assert t.load_config() is None

    def test_not_content(self, caplog: pytest.LogCaptureFixture, tmp_path: Path):
        path = tmp_path / "empty.json"
        path.write_text("{}")

        with caplog.at_level(logging.INFO):
            assert t.load_config(path) is None

        assert "Read secrets.env config from " in caplog.text
        assert "No request specificied." in caplog.text

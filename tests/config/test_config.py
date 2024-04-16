from pathlib import Path

import pytest

from secrets_env.config import load_local_config
from secrets_env.config.parser import Request
from secrets_env.exceptions import ConfigError
from secrets_env.providers.debug import DebugProvider
from secrets_env.providers.plain import PlainTextProvider


class TestLoadLocalConfig:

    def test_success_1(self, tmp_path: Path):
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            """
            [[sources]]
            name = "strangers"
            type = "plain"

            [[secrets]]
            name = "TEST_VAR"
            source = "strangers"
            """
        )

        config = load_local_config(config_path)

        assert len(config.providers) == 1
        assert config.providers["strangers"] == PlainTextProvider(name="strangers")
        assert len(config.requests) == 1
        assert config.requests[0] == Request(name="TEST_VAR", source="strangers")

    def test_success_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """
            sources:
              type: "debug"
              value: "never gonna give you up"

            secrets:
              TEST_VAR: foo
            """
        )
        monkeypatch.setattr(
            "secrets_env.config.find_local_config_file", lambda: config_path
        )

        config = load_local_config(None)

        assert len(config.providers) == 1
        assert config.providers[None] == DebugProvider(value="never gonna give you up")
        assert len(config.requests) == 1
        assert config.requests[0] == Request(name="TEST_VAR", value="foo")

    def test_no_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.config.find_local_config_file", lambda: None)
        with pytest.raises(ConfigError, match="Config file not found"):
            load_local_config(None)

    def test_parse_error(self, caplog: pytest.LogCaptureFixture, tmp_path: Path):
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            """
            [[sources]]
            type = "debug"

            [[secrets]]
            name = "invalid.x"
            """
        )

        with pytest.raises(ConfigError, match="Failed to parse the config"):
            load_local_config(config_path)

        assert (
            '➜ <mark>sources.0.value</mark> (input= <data>{"type": "debug"}</data>)'
            in caplog.text
        )
        assert (
            "➜ <mark>secrets.0.name</mark> (input= <data>invalid.x</data>)"
            in caplog.text
        )

from pathlib import Path

import pytest
from dirty_equals import IsInstance
from pydantic import HttpUrl

from secrets_env.config import load_local_config, load_user_config
from secrets_env.config.parser import Request
from secrets_env.exceptions import ConfigError
from secrets_env.providers.debug import AsyncDebugProvider
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

        assert config.sources == [IsInstance(PlainTextProvider)]
        assert config.secrets == [IsInstance(Request)]

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

        assert config.sources == [IsInstance(AsyncDebugProvider)]
        assert config.secrets == [IsInstance(Request)]

    def test_success_3(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """
            sources:
              type: plain
            """
        )
        monkeypatch.setenv("SECRETS_ENV_CONFIG_FILE", str(config_path))

        config = load_local_config(None)

        assert config.sources == [IsInstance(PlainTextProvider)]
        assert config.secrets == []

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

        with pytest.raises(ConfigError, match="Failed to parse config"):
            load_local_config(config_path)

        assert (
            '➜ <mark>sources.0.value</mark> (input= <data>{"type": "debug", "name": "debug"}</data>)'
            in caplog.text
        )
        assert (
            "➜ <mark>secrets.0.name</mark> (input= <data>invalid.x</data>)"
            in caplog.text
        )


class TestLoadUserConfig:
    def test_success(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        config_path = tmp_path / "config.json"
        config_path.write_text(
            """
            {
                "example.com": {
                    "demo": "value"
                }
            }
            """
        )
        monkeypatch.setattr(
            "secrets_env.config.find_user_config_file", lambda: config_path
        )

        config = load_user_config(HttpUrl("HTTP://EXAMPLE.COM"))
        assert config == {"demo": "value"}

    def test_file_not_exist(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.config.find_user_config_file", lambda: Path("/no-this-file")
        )
        config = load_user_config(HttpUrl("http://example.com"))
        assert config == {}

    def test_file_invalid(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        config_path = tmp_path / "config.json"
        config_path.write_text("{")
        monkeypatch.setattr(
            "secrets_env.config.find_user_config_file", lambda: config_path
        )

        config = load_user_config(HttpUrl("http://example.com"))
        assert config == {}
        assert "User config file is invalid" in caplog.text

    def test_host_not_exist(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        config_path = tmp_path / "config.json"
        config_path.write_text(
            """
            {
                "example.com": {
                    "demo": "value"
                }
            }
            """
        )
        monkeypatch.setattr(
            "secrets_env.config.find_user_config_file", lambda: config_path
        )

        config = load_user_config(HttpUrl("http://unknown.com"))
        assert config == {}

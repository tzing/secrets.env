from pathlib import Path

import pytest

from secrets_env.config import load_local_config
from secrets_env.config.parser import Request
from secrets_env.exceptions import ConfigError
from secrets_env.providers.null import NullProvider


class TestLoadLocalConfig:

    def test_success_1(self, tmp_path: Path):
        config_path = tmp_path / "config.toml"
        config_path.write_text(
            """
            [[sources]]
            type = "null"
            name = "pandora's box"

            [[secrets]]
            name = "TEST_VAR"
            source = "pandora's box"
            """
        )

        config = load_local_config(config_path)

        assert len(config.providers) == 1
        assert config.providers["pandora's box"] == NullProvider(name="pandora's box")
        assert len(config.requests) == 1
        assert config.requests[0] == Request(name="TEST_VAR", source="pandora's box")

    def test_success_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            """
            sources:
              type: "null"

            secrets:
              TEST_VAR: foo
            """
        )
        monkeypatch.setattr(
            "secrets_env.config.find_local_config_file", lambda: config_path
        )

        config = load_local_config(None)

        assert len(config.providers) == 1
        assert config.providers[None] == NullProvider()
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
            name = "pandora's box"
            type = "vault"
            auth = "token"

            [[secrets]]
            name = "1nvalid"
            source = "pandora's box"
            """
        )

        with pytest.raises(ConfigError, match="Failed to parse the config"):
            load_local_config(config_path)

        assert "sources.0.url (input= None)" in caplog.text

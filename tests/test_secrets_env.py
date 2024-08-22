import os
from pathlib import Path

import pytest

from secrets_env import read_values
from secrets_env.exceptions import ConfigError, NoValue


class TestReadValues:
    def test_vault(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        if "VAULT_ADDR" not in os.environ:
            raise pytest.skip("VAULT_ADDR is not set")
        if "VAULT_TOKEN" not in os.environ:
            raise pytest.skip("VAULT_TOKEN is not set")

        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            name = "strongbox"
            type = "vault"
            auth = "token"

            [[secrets]]
            name = "DEMO"
            path = "kv2/test"
            field = ["test", "name.with-dot"]
            """
        )

        with caplog.at_level("DEBUG"):
            values = read_values(config=config_file, strict=True)

        assert values == {"DEMO": "sample-value"}
        assert "Loaded <data>DEMO</data>" in caplog.text
        assert "<mark>1</mark> secrets loaded" in caplog.text

    def test_plain_text(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
            sources:
              type: plain

            secrets:
              DEMO: Hello, World!
            """
        )

        with caplog.at_level("INFO"):
            values = read_values(config=config_file, strict=True)

        assert values == {"DEMO": "Hello, World!"}
        assert "<mark>1</mark> secrets loaded" in caplog.text

    def test_multiple_sources(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
            sources:
              - name: demo-1
                type: plain
              - name: demo-2
                type: debug
                value: Foobar

            secrets:
              - name: DEMO_1
                source: demo-1
                value: Hello, World!
              - name: DEMO_2
                source: demo-2
            """
        )

        with caplog.at_level("DEBUG"):
            values = read_values(config=config_file, strict=True)

        assert values == {"DEMO_1": "Hello, World!", "DEMO_2": "Foobar"}
        assert "Loaded <data>DEMO_1</data>"
        assert "Loaded <data>DEMO_2</data>"
        assert "<mark>2</mark> secrets loaded" in caplog.text

    def test_empty(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"
            """
        )

        with caplog.at_level("DEBUG"):
            values = read_values(config=config_file, strict=True)

        assert values == {}
        assert "Requests are absent." in caplog.text

    def test_no_value__strict(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"

            [[secrets]]
            name = "DEMO"
            """
        )

        with pytest.raises(NoValue):
            read_values(config=config_file, strict=True)

        assert "Value for <data>DEMO</data> not found" in caplog.text
        assert "<error>0</error> / 1 secrets loaded" in caplog.text

    def test_no_value__tolerated(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"

            [[secrets]]
            name = "DEMO"

            [[secrets]]
            name = "FOO"
            value = "Bar"
            """
        )

        values = read_values(config=config_file, strict=False)
        assert values == {"FOO": "Bar"}

        assert "Value for <data>DEMO</data> not found" in caplog.text
        assert "<error>1</error> / 2 secrets loaded" in caplog.text

    def test_config_error(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "non-existent-source"
            """
        )

        with pytest.raises(ConfigError):
            read_values(config=config_file, strict=True)

    def test_disable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"

            [[secrets]]
            name = "DEMO"
            """
        )

        monkeypatch.setenv("SECRETS_ENV_DISABLE", "1")

        values = read_values(config=config_file, strict=True)
        assert values == {}

        assert "The value loading process will be bypassed" in caplog.text

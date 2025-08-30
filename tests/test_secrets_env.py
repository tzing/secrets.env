from pathlib import Path

import pytest

from secrets_env import read_values
from secrets_env.exceptions import ConfigError, NoValue


class TestReadValues:

    @pytest.mark.asyncio
    async def test_plain_text(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
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
            values = await read_values(config=config_file, strict=True)

        assert values == {"DEMO": "Hello, World!"}
        assert "<mark>1</mark> secrets loaded" in caplog.text

    @pytest.mark.asyncio
    async def test_multiple_sources(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
            sources:
              - name: demo-1
                type: debug:async
                value: FooBar
              - name: demo-2
                type: debug:sync
                value: BazQax

            secrets:
              - name: DEMO_1
                source: demo-1
              - name: DEMO_2
                source: demo-2
            """
        )

        with caplog.at_level("DEBUG"):
            values = await read_values(config=config_file, strict=True)

        assert values == {"DEMO_1": "FooBar", "DEMO_2": "BazQax"}
        assert "Loading <data>DEMO_1</data>" in caplog.text
        assert "Loading <data>DEMO_2</data>" in caplog.text
        assert "<mark>2</mark> secrets loaded" in caplog.text

    @pytest.mark.asyncio
    async def test_empty(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"
            """
        )

        with caplog.at_level("DEBUG"):
            values = await read_values(config=config_file, strict=True)

        assert values == {}
        assert "Requests are absent." in caplog.text

    @pytest.mark.asyncio
    async def test_no_value__strict(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
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

        with pytest.raises(NoValue):
            await read_values(config=config_file, strict=True)

        assert "Value for <data>DEMO</data> not found" in caplog.text
        assert "<error>0</error> / 1 secrets loaded" in caplog.text

    @pytest.mark.asyncio
    async def test_no_value__tolerated(
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

        values = await read_values(config=config_file, strict=False)
        assert values == {"FOO": "Bar"}

        assert "Value for <data>DEMO</data> not found" in caplog.text
        assert "<error>1</error> / 2 secrets loaded" in caplog.text

    @pytest.mark.asyncio
    async def test_config_error(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "non-existent-source"
            """
        )

        with pytest.raises(ConfigError):
            await read_values(config=config_file, strict=True)

    @pytest.mark.asyncio
    async def test_disable(
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

        values = await read_values(config=config_file, strict=True)
        assert values == {}

        assert "The value loading process will be bypassed" in caplog.text

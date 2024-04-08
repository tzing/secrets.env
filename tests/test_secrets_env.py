from pathlib import Path

import pytest

from secrets_env import read_values
from secrets_env.config import LocalConfig


class TestReadValues:
    def test_plain_text(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"

            [[secrets]]
            name = "DEMO"
            value = "Hello, World!"
            """
        )

        assert read_values(config=config_file, strict=True) == {"DEMO": "Hello, World!"}

    def test_empty(self, tmp_path: Path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            """
            [[sources]]
            type = "plain"
            """
        )

        assert read_values(config=config_file, strict=True) == {}

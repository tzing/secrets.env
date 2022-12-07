import logging
from pathlib import Path

import pytest

import secrets_env.config as t
from secrets_env.config.finder import ConfigFile
from secrets_env.providers.vault.auth.null import NoAuth


class TestLoadConfig:
    @pytest.mark.parametrize(
        ("filename", "format_"),
        [
            (".secrets-env.json", "json"),
            (".secrets-env.toml", "toml"),
            (".secrets-env.yaml", "yaml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success_1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        repo_path: Path,
        filename: str,
        format_: str,
    ):
        """Auto config finding"""
        # setup
        def find_config_file():
            return ConfigFile(
                filename, format_, repo_path / "tests" / "fixtures" / filename
            )

        monkeypatch.setattr(t, "find_config_file", find_config_file)

        # run
        cfg = t.load_config()

        # test
        self.assert_config_format(cfg)

    @pytest.mark.parametrize(
        ("source", "rename"),
        [
            (".secrets-env.json", "sample.json"),
            (".secrets-env.toml", "sample.toml"),
            (".secrets-env.yaml", "sample.yml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success_2(self, tmp_path: Path, repo_path: Path, source: str, rename: str):
        """Manual given file"""
        # setup
        src_path = repo_path / "tests" / "fixtures" / source
        dst_path = tmp_path / rename
        dst_path.write_bytes(src_path.read_bytes())

        # run
        cfg = t.load_config(src_path)

        # test
        self.assert_config_format(cfg)

    def assert_config_format(self, cfg: dict):
        assert isinstance(cfg, dict)
        assert cfg["client"]["url"] == "https://example.com/"
        assert cfg["client"]["auth"] == NoAuth()
        assert cfg["secrets"] == {
            "VAR1": ("kv/default", "example"),
            "VAR2": ("kv/default", "example"),
        }

    def test_not_found(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "find_config_file", lambda: None)
        assert t.load_config() is None

    def test_not_content(self, caplog: pytest.LogCaptureFixture, tmp_path: Path):
        path = tmp_path / "empty.json"
        path.write_text("{}")

        with caplog.at_level(logging.INFO):
            assert t.load_config(path) is None

        assert "Read secrets.env config from " in caplog.text
        assert "No target specificied." in caplog.text

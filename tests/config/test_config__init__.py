import logging
from pathlib import Path

import pytest

import secrets_env.config as t
from secrets_env.auth import TokenAuth
from secrets_env.config.types import Config, ConfigFileMetadata, SecretPath


class TestLoadConfig:
    @pytest.mark.parametrize(
        ("filename", "spec"),
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
        spec: str,
    ):
        # fixtures
        def find_config_file():
            return ConfigFileMetadata(
                filename, spec, True, repo_path / "example" / filename
            )

        monkeypatch.setattr(t, "find_config_file", find_config_file)
        monkeypatch.setenv("SECRETS_ENV_TOKEN", "ex@mp1e")

        # run
        cfg = t.load_config()

        # test
        assert isinstance(cfg, Config)
        assert cfg.url == "https://example.com/"
        assert cfg.auth == TokenAuth("ex@mp1e")
        assert cfg.secret_specs == {
            "VAR1": SecretPath("kv/default", "example"),
            "VAR2": SecretPath("kv/default", "example"),
        }

    @pytest.mark.parametrize(
        "filename",
        [
            ".secrets-env.json",
            ".secrets-env.toml",
            ".secrets-env.yaml",
            "pyproject.toml",
        ],
    )
    def test_success_2(
        self, monkeypatch: pytest.MonkeyPatch, repo_path: Path, filename: str
    ):
        monkeypatch.setenv("SECRETS_ENV_TOKEN", "ex@mp1e")

        path = repo_path / "example" / filename
        cfg = t.load_config(path)

        assert isinstance(cfg, Config)
        assert cfg.url == "https://example.com/"
        assert cfg.auth == TokenAuth("ex@mp1e")
        assert cfg.secret_specs == {
            "VAR1": SecretPath("kv/default", "example"),
            "VAR2": SecretPath("kv/default", "example"),
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
        assert "No content in the config file." in caplog.text

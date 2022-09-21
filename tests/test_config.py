import logging
import os
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

import secrets_env.auth
from secrets_env import config
from secrets_env.config import Config, ConfigFile, SecretResource


class TestLoadConfig:
    @pytest.mark.parametrize(
        ("filename", "format_"),
        [
            (".secrets-env.json", "json"),
            (".secrets-env.yaml", "yaml"),
            (".secrets-env.toml", "toml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    @patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "ex@mp1e"})
    def test_success(self, example_config_dir: Path, filename: str, format_: str):
        # create config spec
        spec = ConfigFile(
            "mock",
            format_,
            True,
            example_config_dir / filename,
        )

        # run
        with patch("secrets_env.config.find_config", return_value=spec):
            assert config.load_config() == Config(
                url="https://example.com/",
                auth=secrets_env.auth.TokenAuth("ex@mp1e"),
                secret_specs={
                    "VAR1": SecretResource("kv/default", "example"),
                    "VAR2": SecretResource("kv/default", "example"),
                },
            )

    @pytest.fixture()
    def find_config(self):
        with patch("secrets_env.config.find_config") as mock:
            yield mock

    def test_config_not_found(
        self, caplog: pytest.LogCaptureFixture, find_config: Mock
    ):
        find_config.return_value = None
        with caplog.at_level(logging.DEBUG):
            assert config.load_config() is None
        assert "Config file not found." in caplog.text

    def test_config_empty(self, caplog: pytest.LogCaptureFixture, find_config: Mock):
        find_config.return_value = ConfigFile("mock", "json", True, "mock")
        with caplog.at_level(logging.DEBUG), patch(
            "secrets_env.config.load_json_file", return_value={}
        ):
            assert config.load_config() is None
        assert "Configure section not found." in caplog.text

    def test_parse_error(self, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.config.use_config",
            return_value=ConfigFile("mock", "json", True, "mock"),
        ), caplog.at_level(logging.WARNING), patch(
            "secrets_env.config.load_json_file", return_value={"foo": "bar"}
        ):
            assert config.load_config("mock") is None


class TestLoads:
    @patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "ex@mp1e"})
    def test_success_from_config(self):
        out, ok = config._loads(
            {
                "source": {
                    "url": "https://example.com/",
                    "auth": {
                        "method": "token",
                    },
                },
                "secrets": {
                    "VAR1": "example#val1",
                    "VAR2": {"path": "example", "key": "val2"},
                    "3VAR": "example#val3",  # name invalid
                },
            }
        )

        assert ok is True
        assert isinstance(out, Config)
        assert out.url == "https://example.com/"
        assert out.auth == secrets_env.auth.TokenAuth("ex@mp1e")
        assert out.secret_specs == {
            "VAR1": SecretResource("example", "val1"),
            "VAR2": SecretResource("example", "val2"),
        }

    @patch.dict(
        "os.environ",
        {
            "SECRETS_ENV_ADDR": "https://example.com/",
            "SECRETS_ENV_METHOD": "token",
            "SECRETS_ENV_TOKEN": "ex@mp1e",
        },
    )
    def test_success_from_env(self):
        out, ok = config._loads(
            {
                "secrets": {
                    "VAR1": "example#val1",
                    "VAR2": {"path": "example", "key": "val2"},
                    "VAR3": "invalid-path",  # path invalid
                    "VAR4": {"foo": "var"},  # resource invalid
                    "VAR5": 1234,  # type error
                }
            }
        )

        assert ok is True
        assert out.url == "https://example.com/"
        assert out.auth == secrets_env.auth.TokenAuth("ex@mp1e")
        assert out.secret_specs == {
            "VAR1": SecretResource("example", "val1"),
            "VAR2": SecretResource("example", "val2"),
        }

    @patch.dict("os.environ", {"VAULT_ADDR": "https://new.example.com/"})
    def test_success_use_env(self):
        # this test case is setup to make sure env var can overwrite the config
        mock_auth = Mock(spec=secrets_env.auth.Auth)
        with patch("secrets_env.auth.load_auth", return_value=mock_auth):
            out, ok = config._loads(
                {
                    "source": {
                        "url": "https://example.com/",
                        "auth": {},
                    },
                    "secrets": {},
                }
            )

        assert ok is True
        assert isinstance(out, Config)
        assert out.url == "https://new.example.com/"

    @patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "ex@mp1e"})
    def test_success_brief_auth(self):
        out, ok = config._loads(
            {
                "source": {"url": "https://example.com/", "auth": "token"},
                "secrets": {},
            }
        )

        assert ok is True
        assert isinstance(out, Config)
        assert out.auth == secrets_env.auth.TokenAuth("ex@mp1e")

    def test_error(self):
        # missing source data
        spec, ok = config._loads(
            {
                "source": "not-a-dict",
                "secrets": {
                    "VAR": "test#v1",
                },
            }
        )
        assert not ok
        assert spec == Config(
            None,
            None,
            {"VAR": SecretResource("test", "v1")},
        )

        # missing secret data
        spec, ok = config._loads(
            {
                "source": {
                    "url": "https://example.com",
                }
            }
        )
        assert not ok
        assert spec == Config("https://example.com", None, {})

        # secret section invalid
        spec, ok = config._loads(
            {
                "source": {
                    "url": "https://example.com",
                },
                "secrets": "dummy" * 50,
            }
        )
        assert not ok
        assert spec == Config("https://example.com", None, {})

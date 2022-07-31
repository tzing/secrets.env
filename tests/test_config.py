import logging
import os
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

import vault2env.auth
from vault2env import config
from vault2env.config import ConfigFileSpec, ConfigSpec, SecretResource


def test_import_any():
    assert config._import_any("json")
    assert config._import_any("module-not-exists", "json")
    assert config._import_any("module-not-exists") is None


class TestFindConfig:
    @pytest.mark.parametrize(
        ("spec_name", "format_"),
        [
            (".vault2env.json", "json"),
            (".vault2env.yaml", "yaml"),
            (".vault2env.yml", "yaml"),
            (".vault2env.toml", "toml"),
            ("pyproject.toml", "pyproject.toml"),
        ],
    )
    def test_success(
        self,
        tmpdir: str,
        spec_name: str,
        format_: str,
    ):
        # create fake config file
        mock_config = Path(tmpdir) / spec_name
        mock_config.touch()

        # run test
        os.chdir(tmpdir)
        assert config.find_config() == ConfigFileSpec(
            spec_name,
            format_,
            True,
            mock_config,
        )

    def test_exists_multiple(self, tmpdir: str):
        tmpdir = Path(tmpdir)
        (tmpdir / ".vault2env.json").touch()
        (tmpdir / ".vault2env.yaml").touch()
        (tmpdir / ".vault2env.toml").touch()

        os.chdir(tmpdir)
        assert config.find_config() == ConfigFileSpec(
            ".vault2env.toml",
            "toml",
            True,
            tmpdir / ".vault2env.toml",
        )

    def test_config_not_enabled(self, tmpdir: str):
        tmpdir = Path(tmpdir)
        (tmpdir / ".vault2env.json").touch()
        (tmpdir / ".vault2env.yaml").touch()
        (tmpdir / ".vault2env.toml").touch()

        os.chdir(tmpdir)
        with patch(
            "vault2env.config.ORDERED_CONFIG_FILE_SPECS",
            [
                ConfigFileSpec(".vault2env.toml", "toml", False),
                ConfigFileSpec(".vault2env.yaml", "yaml", False),
                ConfigFileSpec(".vault2env.json", "json", True),
            ],
        ):
            assert config.find_config() == ConfigFileSpec(
                ".vault2env.json",
                "json",
                True,
                tmpdir / ".vault2env.json",
            )

    def test_no_config(self, tmpdir: str):
        os.chdir(tmpdir)
        assert config.find_config() is None


class TestLoadConfig:
    @pytest.mark.parametrize(
        ("fixture_name", "format_"),
        [
            ("example.json", "json"),
            ("example.yaml", "yaml"),
            ("example.toml", "toml"),
            ("example-pyproject.toml", "pyproject.toml"),
        ],
    )
    @patch.dict("os.environ", {"VAULT_TOKEN": "ex@mp1e"})
    def test_success(
        self,
        fixture_name: str,
        format_: str,
    ):
        # create config spec
        test_dir = Path(__file__).resolve().absolute().parent
        spec = ConfigFileSpec(
            "mock",
            format_,
            True,
            test_dir / "fixtures" / fixture_name,
        )

        # run
        with patch("vault2env.config.find_config", return_value=spec):
            assert config.load_config() == ConfigSpec(
                url="https://example.com/",
                auth=vault2env.auth.TokenAuth("ex@mp1e"),
                secret_specs={
                    "VAR1": SecretResource("kv/default", "example"),
                    "VAR2": SecretResource("kv/default", "example"),
                },
            )

    @pytest.fixture()
    def find_config(self):
        with patch("vault2env.config.find_config") as mock:
            yield mock

    def test_config_not_found(
        self, caplog: pytest.LogCaptureFixture, find_config: Mock
    ):
        find_config.return_value = None
        with caplog.at_level(logging.DEBUG):
            assert config.load_config() is None
        assert "Config file not found." in caplog.text

    def test_config_malformed(
        self, caplog: pytest.LogCaptureFixture, find_config: Mock
    ):
        find_config.return_value = ConfigFileSpec("mock", "json", True, "mock")
        with caplog.at_level(logging.WARNING), patch(
            "vault2env.config.load_json_file", return_value=["array data"]
        ):
            assert config.load_config() is None
        assert "Configuration file is malformed." in caplog.text

    def test_config_runtime_error(self, find_config: Mock):
        find_config.return_value = ConfigFileSpec("mock", "malformed", True)
        with pytest.raises(RuntimeError):
            config.load_config()

    def test_config_empty(self, caplog: pytest.LogCaptureFixture, find_config: Mock):
        find_config.return_value = ConfigFileSpec("mock", "json", True, "mock")
        with caplog.at_level(logging.DEBUG), patch(
            "vault2env.config.load_json_file", return_value={}
        ):
            assert config.load_config() is None
        assert "Configure section not found." in caplog.text

    def test_parse_error(self, caplog: pytest.LogCaptureFixture, find_config: Mock):
        find_config.return_value = ConfigFileSpec("mock", "json", True, "mock")
        with caplog.at_level(logging.WARNING), patch(
            "vault2env.config.load_json_file", return_value={"foo": "bar"}
        ):
            assert config.load_config() is None

    def test_load_file(self):
        with patch("builtins.open", mock_open(read_data=b"[]")):
            assert config.load_toml_file("mocked") is None

        with patch("builtins.open", mock_open(read_data=b":\x0a")):
            assert config.load_yaml_file("mocked") is None

        with patch("builtins.open", mock_open(read_data=b"{")):
            assert config.load_json_file("mocked") is None


class TestExtract:
    @patch.dict("os.environ", {"VAULT_TOKEN": "ex@mp1e"})
    def test_success_from_config(self):
        assert config.extract(
            {
                "core": {
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
        ) == (
            ConfigSpec(
                "https://example.com/",
                vault2env.auth.TokenAuth("ex@mp1e"),
                {
                    "VAR1": SecretResource("example", "val1"),
                    "VAR2": SecretResource("example", "val2"),
                },
            ),
            True,
        )

    @patch.dict(
        "os.environ",
        {
            "VAULT_ADDR": "https://example.com/",
            "VAULT_METHOD": "token",
            "VAULT_TOKEN": "ex@mp1e",
        },
    )
    def test_success_from_env(self):
        assert config.extract(
            {
                "secrets": {
                    "VAR1": "example#val1",
                    "VAR2": {"path": "example", "key": "val2"},
                    "VAR3": "invalid-path",  # path invalid
                    "VAR4": {"foo": "var"},  # resource invalid
                    "VAR5": 1234,  # type error
                }
            }
        ) == (
            ConfigSpec(
                "https://example.com/",
                vault2env.auth.TokenAuth("ex@mp1e"),
                {
                    "VAR1": SecretResource("example", "val1"),
                    "VAR2": SecretResource("example", "val2"),
                },
            ),
            True,
        )

    def test_error(self):
        # missing core data
        spec, ok = config.extract(
            {
                "core": "not-a-dict",
                "secrets": {
                    "VAR": "test#v1",
                },
            }
        )
        assert not ok
        assert spec == ConfigSpec(
            None,
            None,
            {"VAR": SecretResource("test", "v1")},
        )

        # missing secret data
        spec, ok = config.extract(
            {
                "core": {
                    "url": "https://example.com",
                }
            }
        )
        assert not ok
        assert spec == ConfigSpec("https://example.com", None, {})

        # secret section invalid
        spec, ok = config.extract(
            {
                "core": {
                    "url": "https://example.com",
                },
                "secrets": "dummy" * 50,
            }
        )
        assert not ok
        assert spec == ConfigSpec("https://example.com", None, {})


class TestBuildAuth:
    def test_success(self):
        # token
        with patch.dict("os.environ", {"VAULT_TOKEN": "ex@mp1e"}):
            assert config.build_auth({"method": "token"}) == vault2env.auth.TokenAuth(
                "ex@mp1e"
            )

        # auth
        with patch.dict("os.environ", {"VAULT_PASSWORD": "P@ssw0rd"}):
            assert config.build_auth(
                {"method": "okta", "username": "test@example.com"}
            ) == vault2env.auth.OktaAuth("test@example.com", "P@ssw0rd")

    def test_shortcut(self):
        with patch.dict("os.environ", {"VAULT_TOKEN": "ex@mp1e"}):
            assert config.build_auth("token") == vault2env.auth.TokenAuth("ex@mp1e")

    def test_type_error(self, caplog: pytest.LogCaptureFixture):
        assert config.build_auth(1234) is None
        assert "Config malformed: <data>auth</data>." in caplog.text

    @patch.dict("os.environ", {"VAULT_METHOD": "token", "VAULT_TOKEN": "ex@mp1e"})
    def test_from_env(self):
        assert config.build_auth({}) == vault2env.auth.TokenAuth("ex@mp1e")

    def test_missing_method(self, caplog: pytest.LogCaptureFixture):
        assert config.build_auth({}) is None
        assert "Missing required config: <data>auth method</data>." in caplog.text

    def test_unknown_method(self, caplog: pytest.LogCaptureFixture):
        assert config.build_auth({"method": "invalid-method"}) is None
        assert "Unknown auth method: <data>invalid-method</data>" in caplog.text


def test_has_warned_lang_support_issue():
    assert config.has_warned_lang_support_issue("TEST") is False
    assert config.has_warned_lang_support_issue("TEST") is True
    assert config.has_warned_lang_support_issue("TEST") is True
    assert config.has_warned_lang_support_issue("TEST2") is False

import logging
import os
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

import secrets_env.auth
from secrets_env import config
from secrets_env.config import ConfigFileSpec, ConfigSpec, SecretResource


def test_import_any():
    assert config._import_any("json")
    assert config._import_any("module-not-exists", "json")
    assert config._import_any("module-not-exists") is None


@pytest.fixture()
def example_config_dir():
    this_file = Path(__file__).resolve()
    this_repo = this_file.parent.parent
    return this_repo / "example"


class TestFindConfig:
    @pytest.mark.parametrize(
        "filename",
        [
            ".secrets-env.json",
            ".secrets-env.yaml",
            ".secrets-env.yml",
            ".secrets-env.toml",
            "pyproject.toml",
        ],
    )
    def test_success(self, tmpdir: Path, filename: str):
        # create fake config file
        tmpdir = Path(tmpdir)
        (tmpdir / filename).touch()
        (tmpdir / ".garbage").touch()

        # run test
        out = config.find_config(tmpdir)
        assert out.filename == filename
        assert out.path == (tmpdir / filename).absolute()

    def test_exists_multiple(self, example_config_dir: Path):
        # we must have TOML installed in testing env
        assert config.find_config(example_config_dir) == ConfigFileSpec(
            ".secrets-env.toml",
            "toml",
            True,
            example_config_dir / ".secrets-env.toml",
        )

    def test_config_not_enabled(self, example_config_dir: Path):
        with patch(
            "secrets_env.config.ORDERED_CONFIG_FILE_SPECS",
            [
                ConfigFileSpec(".secrets-env.toml", "toml", False),
                ConfigFileSpec(".secrets-env.yaml", "yaml", False),
                ConfigFileSpec(".secrets-env.json", "json", True),
            ],
        ):
            assert config.find_config(example_config_dir) == ConfigFileSpec(
                ".secrets-env.json",
                "json",
                True,
                example_config_dir / ".secrets-env.json",
            )

    def test_no_config(self, tmpdir: str):
        os.chdir(tmpdir)
        assert config.find_config() is None


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
        spec = ConfigFileSpec(
            "mock",
            format_,
            True,
            example_config_dir / filename,
        )

        # run
        with patch("secrets_env.config.find_config", return_value=spec):
            assert config.load_config() == ConfigSpec(
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

    def test_config_malformed(
        self, caplog: pytest.LogCaptureFixture, find_config: Mock
    ):
        find_config.return_value = ConfigFileSpec("mock", "json", True, "mock")
        with caplog.at_level(logging.WARNING), patch(
            "secrets_env.config.load_json_file", return_value=["array data"]
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
            "secrets_env.config.load_json_file", return_value={}
        ):
            assert config.load_config() is None
        assert "Configure section not found." in caplog.text

    def test_parse_error(self, caplog: pytest.LogCaptureFixture, find_config: Mock):
        find_config.return_value = ConfigFileSpec("mock", "json", True, "mock")
        with caplog.at_level(logging.WARNING), patch(
            "secrets_env.config.load_json_file", return_value={"foo": "bar"}
        ):
            assert config.load_config() is None

    def test_load_file_error(self):
        with patch("builtins.open", mock_open(read_data=b"[]")):
            assert config.load_toml_file("mocked") is None

        with patch("builtins.open", mock_open(read_data=b":\x0a")):
            assert config.load_yaml_file("mocked") is None

        with patch("builtins.open", mock_open(read_data=b"{")):
            assert config.load_json_file("mocked") is None


class TestExtract:
    @patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "ex@mp1e"})
    def test_success_from_config(self):
        out, ok = config.extract(
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
        assert isinstance(out, ConfigSpec)
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
        out, ok = config.extract(
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
        with patch("secrets_env.config.load_auth", return_value=mock_auth):
            out, ok = config.extract(
                {
                    "source": {
                        "url": "https://example.com/",
                        "auth": {},
                    },
                    "secrets": {},
                }
            )

        assert ok is True
        assert isinstance(out, ConfigSpec)
        assert out.url == "https://new.example.com/"

    def test_error(self):
        # missing source data
        spec, ok = config.extract(
            {
                "source": "not-a-dict",
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
                "source": {
                    "url": "https://example.com",
                }
            }
        )
        assert not ok
        assert spec == ConfigSpec("https://example.com", None, {})

        # secret section invalid
        spec, ok = config.extract(
            {
                "source": {
                    "url": "https://example.com",
                },
                "secrets": "dummy" * 50,
            }
        )
        assert not ok
        assert spec == ConfigSpec("https://example.com", None, {})


class TestLoadAuth:
    def test_shortcut(self):
        with patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "ex@mp1e"}):
            assert config.load_auth("token") == secrets_env.auth.TokenAuth("ex@mp1e")

    def test_type_error(self, caplog: pytest.LogCaptureFixture):
        assert config.load_auth(1234) is None
        assert "Config malformed: <data>auth</data>." in caplog.text


def test_warn_lang_support_issue():
    assert config.warn_lang_support_issue("TEST") is True
    assert config.warn_lang_support_issue("TEST") is False
    assert config.warn_lang_support_issue("TEST") is False
    assert config.warn_lang_support_issue("TEST-2") is True

import builtins
from pathlib import Path
from unittest.mock import Mock, mock_open

import pytest

import secrets_env.config.reader as t
from secrets_env.config.finder import ConfigFile
from secrets_env.exception import UnsupportedError


class TestReadConfigFile:
    @pytest.mark.parametrize(
        ("lang", "mock_func"),
        [
            ("toml", "read_toml_file"),
            ("yaml", "read_yaml_file"),
            ("json", "read_json_file"),
        ],
    )
    def test_success(self, monkeypatch: pytest.MonkeyPatch, lang: str, mock_func: str):
        monkeypatch.setattr(t, mock_func, lambda _: {"test": "mocked"})

        spec = Mock(
            spec=ConfigFile,
            lang=lang,
            format=lang,
            path=Mock(spec=Path),
        )
        assert t.read_config_file(spec) == {"test": "mocked"}

    def test_success_pyproject(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            t,
            "read_toml_file",
            lambda _: {
                "tool": {
                    "secrets-env": {"test": "mocked"},
                }
            },
        )

        spec = Mock(
            spec=ConfigFile,
            lang="toml",
            format="pyproject.toml",
            path=Mock(spec=Path),
        )
        assert t.read_config_file(spec) == {"test": "mocked"}

    @pytest.mark.parametrize(
        "read_file_output",
        [
            {},
            None,
            {"tool": {}},
            {"tool": {"secrets-env": None}},
            {"tool": {"secrets-env": {}}},
        ],
    )
    def test_empty(self, monkeypatch: pytest.MonkeyPatch, read_file_output):
        monkeypatch.setattr(t, "read_toml_file", lambda _: read_file_output)

        spec = Mock(
            spec=ConfigFile, lang="toml", format="pyproject.toml", path=Mock(spec=Path)
        )

        assert t.read_config_file(spec) == {}

    def test_unknown_format(self):
        spec = Mock(
            spec=ConfigFile, lang="unknown", format="unknown", path=Mock(spec=Path)
        )
        with pytest.raises(UnsupportedError):
            t.read_config_file(spec)


class TestReadFile:
    def test_toml(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b"["))
        assert t.read_toml_file("mocked") is None

    def test_yaml(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b":\x0a"))
        assert t.read_yaml_file("mocked") is None

    def test_json(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(builtins, "open", mock_open(read_data=b"{"))
        assert t.read_json_file("mocked") is None

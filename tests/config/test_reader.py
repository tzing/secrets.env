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

    def test_malformed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "read_json_file", lambda _: "a string")
        spec = Mock(spec=ConfigFile, lang="json", format="json", path=Mock(spec=Path))
        assert t.read_config_file(spec) == {}


@pytest.mark.parametrize(
    ("parsed", "source"),
    [
        # success
        (
            {"test": {"foo": "bar"}},
            b"""\
            [test]
            foo = "bar"
            """,
        ),
        # exception
        (None, b"["),
    ],
)
def test_read_toml_file(monkeypatch: pytest.MonkeyPatch, source: bytes, parsed: dict):
    monkeypatch.setattr(builtins, "open", mock_open(read_data=source))
    path = Mock(spec=Path)
    assert t.read_toml_file(path) == parsed


@pytest.mark.parametrize(
    ("parsed", "source"),
    [
        # success
        (
            {"test": {"foo": "bar"}},
            b"""
            test:
                foo: bar
            """,
        ),
        # exception
        (None, b":\x0a"),
    ],
)
def test_read_yaml_file(monkeypatch: pytest.MonkeyPatch, source: bytes, parsed: dict):
    monkeypatch.setattr(builtins, "open", mock_open(read_data=source))
    path = Mock(spec=Path)
    assert t.read_yaml_file(path) == parsed


@pytest.mark.parametrize(
    ("parsed", "source"),
    [
        # success
        ({"foo": "bar"}, b'{"foo": "bar"}'),
        # exception
        (None, b"{"),
    ],
)
def test_read_json_file(monkeypatch: pytest.MonkeyPatch, source: bytes, parsed: dict):
    monkeypatch.setattr(builtins, "open", mock_open(read_data=source))
    path = Mock(spec=Path)
    assert t.read_json_file(path) == parsed

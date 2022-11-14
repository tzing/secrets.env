import builtins
from unittest.mock import mock_open

import pytest

import secrets_env.config.reader as t


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

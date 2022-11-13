import sys
from unittest.mock import patch

import click
import keyring.errors
import pytest

import secrets_env.io as t


def test_get_env_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_ITEM_1", "value-1")
    monkeypatch.setenv("SECRETS_ENV_ITEM_2", "value-2")

    assert t.get_env_var("SECRETS_ENV_ITEM_1") == "value-1"
    assert t.get_env_var("SECRETS_ENV_ITEM_1", "SECRETS_ENV_ITEM_2") == "value-1"
    assert t.get_env_var("NO_THIS_ENV", "SECRETS_ENV_ITEM_2") == "value-2"
    assert t.get_env_var("NO_THIS_ENV_1", "NO_THIS_ENV_2") is None


class TestPrompt:
    def test_disable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_PROMPT", "True")
        assert t.prompt("test") is None

    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_PROMPT", "Foo")
        with patch("click.prompt", return_value="buzz"):
            assert t.prompt("test") == "buzz"

    def test_abort(self):
        with patch("click.prompt", side_effect=click.Abort("mock abort")):
            assert t.prompt("test") is None


class TestKeyring:
    def test_success(self):
        with patch("keyring.get_password", return_value="bar"):
            assert t.read_keyring("test") == "bar"

    def test_error(self):
        with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
            assert t.read_keyring("test") is None

    def test_disable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_NO_KEYRING", "True")
        assert t.read_keyring("test") is None

    def test_not_install(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setitem(sys.modules, "keyring", None)
        assert t.read_keyring("test") is None

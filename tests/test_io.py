from unittest.mock import patch

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


def test_read_keyring():
    with patch("keyring.get_password", return_value="bar"):
        assert t.read_keyring("foo") == "bar"
    with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
        assert t.read_keyring("foo") is None

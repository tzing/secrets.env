from unittest.mock import patch

import keyring.errors

import secrets_env.auth.io as t


def test_read_keyring():
    with patch("keyring.get_password", return_value="bar"):
        assert t.read_keyring("foo") == "bar"
    with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
        assert t.read_keyring("foo") is None

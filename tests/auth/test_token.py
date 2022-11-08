from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import httpx
import pytest

import secrets_env.auth.token as t


class TestTokenAuth:
    def setup_method(self):
        self.authobj = t.TokenAuth("T0ken")

    def test__init__(self):
        assert self.authobj.token == "T0ken"

        with pytest.raises(TypeError):
            t.TokenAuth(1234)

    def test__repr__(self):
        assert repr(self.authobj) == "TokenAuth(token='T0ken')"

    def test_method(self):
        assert t.TokenAuth.method() == "token"

    def test_login(self):
        client = Mock(spec=httpx.Client)
        assert self.authobj.login(client) == "T0ken"

    def test_load_env(self, monkeypatch: pytest.MonkeyPatch):
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_TOKEN", "T0ken")
            assert t.TokenAuth.load({}) == self.authobj

        with monkeypatch.context() as m:
            m.setenv("VAULT_TOKEN", "T0ken")
            assert t.TokenAuth.load({}) == self.authobj

    @pytest.fixture()
    def token_helper_file(self):
        mock_path_file = Mock(spec=Path)
        mock_path_file.is_file.return_value = False
        with patch.object(t.Path, "__truediv__", return_value=mock_path_file):
            yield mock_path_file

    def test_load_helper(self, token_helper_file: Mock):
        token_helper_file.is_file.return_value = True
        token_helper_file.open = mock_open(read_data="T0ken")
        assert t.TokenAuth.load({}) == self.authobj

    @pytest.mark.usefixtures("token_helper_file")
    def test_load_keyring(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "read_keyring", lambda _: "T0ken")
        assert t.TokenAuth.load({}) == self.authobj

    @pytest.mark.usefixtures("token_helper_file")
    def test_load_fail(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t, "read_keyring", lambda _: None)
        assert t.TokenAuth.load({}) is None

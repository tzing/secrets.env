import logging
from unittest.mock import Mock, patch, mock_open

import hvac
import keyring.errors
import pytest

from secrets_env import auth


def test_get_password():
    with patch("keyring.get_password", return_value="bar"):
        assert auth.get_password("foo") == "bar"
    with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
        assert auth.get_password("foo") is None


class TestTokenAuth:
    def setup_method(self):
        self.obj = auth.TokenAuth("T0ken")

    def test__init__(self):
        assert self.obj.method() == "token"
        assert self.obj.token == "T0ken"

        with pytest.raises(TypeError):
            auth.TokenAuth(1234)

    def test__repr__(self):
        assert repr(self.obj) == "TokenAuth(token='T0ken')"

    def test_method(self):
        assert auth.TokenAuth.method() == "token"

    def test_apply(self):
        # set up token doesn't trigger connection, so uses real client
        client = hvac.Client("https://example.com")
        self.obj.apply(client)
        assert client.token == "T0ken"

    @pytest.fixture()
    def _no_load_from_home(self):
        with patch.object(auth.TokenAuth, "_load_from_home", return_value=None):
            yield

    @pytest.mark.usefixtures("_no_load_from_home")
    def test_load(self):
        # test `load` without `_load_from_home`

        # success
        with patch.dict("os.environ", {"VAULT_TOKEN": "foo"}):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

        with patch("secrets_env.auth.get_password", return_value="foo"):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

        # no data
        assert auth.TokenAuth.load({}) is None

    def test_load_from_home(self):
        # test `load` with `_load_from_home`
        with patch.object(auth.TokenAuth, "_load_from_home", return_value="foo"):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

    @pytest.fixture()
    def toke_helper_file(self):
        with patch("pathlib.Path.home") as home:
            # Hardcoded path to match the path:
            #   pathlib.Path.home() / ".vault-token"
            yield home.return_value.__truediv__.return_value

    def test__load_from_home_1(self, toke_helper_file: Mock):
        # test `_load_from_home` itself
        # case: success
        toke_helper_file.open = mock_open(read_data="foo\n")
        assert auth.TokenAuth._load_from_home() == "foo"

    def test__load_from_home_2(self, toke_helper_file: Mock):
        # test `_load_from_home` itself
        # case: file not found
        toke_helper_file.is_file.return_value = False
        assert auth.TokenAuth._load_from_home() is None


class TestUserPasswordAuth:
    @pytest.fixture()
    def _unfreeze(self):
        """UserPasswordAuth has some required abstract method not implemented.
        Use this fixture to patch the propertires for running the test."""
        with patch.object(auth.UserPasswordAuth, "__abstractmethods__", set()), patch(
            "secrets_env.auth.UserPasswordAuth.method", return_value="mock"
        ):
            yield

    @pytest.mark.usefixtures("_unfreeze")
    def test___init__(self):
        # success
        obj = auth.UserPasswordAuth("user@example.com", "P@ssw0rd")
        assert obj.username == "user@example.com"
        assert obj.password == "P@ssw0rd"

        # error
        with pytest.raises(TypeError):
            auth.UserPasswordAuth(1234, "P@ssw0rd")
        with pytest.raises(TypeError):
            auth.UserPasswordAuth("user@example.com", 1234)

    @pytest.mark.usefixtures("_unfreeze")
    def test_load_from_env(self):
        # overwrite username
        with patch.dict(
            "os.environ",
            {"VAULT_USERNAME": "user-2@example.com", "VAULT_PASSWORD": "P@ssw0rd"},
        ):
            obj = auth.UserPasswordAuth.load({"username": "user-1@example.com"})
        assert obj == auth.UserPasswordAuth("user-2@example.com", "P@ssw0rd")

        # password only
        with patch.dict(
            "os.environ",
            {"VAULT_PASSWORD": "P@ssw0rd"},
        ):
            obj = auth.UserPasswordAuth.load({"username": "user-1@example.com"})
        assert obj == auth.UserPasswordAuth("user-1@example.com", "P@ssw0rd")

    @pytest.mark.usefixtures("_unfreeze")
    def test_load_from_keyring(self):
        # username + password
        with patch(
            "secrets_env.auth.get_password",
            side_effect=["user-2@example.com", "P@ssw0rd"],
        ) as g:
            obj = auth.UserPasswordAuth.load({})

        assert obj == auth.UserPasswordAuth("user-2@example.com", "P@ssw0rd")
        g.assert_any_call("mock/:username")
        g.assert_any_call("mock/user-2@example.com")

        # from keyring, password only
        with patch("secrets_env.auth.get_password", return_value="P@ssw0rd") as g:
            obj = auth.UserPasswordAuth.load({"username": "user-1@example.com"})

        assert obj == auth.UserPasswordAuth("user-1@example.com", "P@ssw0rd")
        g.assert_any_call("mock/user-1@example.com")

    @pytest.mark.usefixtures("_unfreeze")
    def test_load_mixed(self):
        with patch.dict("os.environ", {"VAULT_PASSWORD": "P@ssw0rd"}), patch(
            "secrets_env.auth.get_password", return_value="user-2@example.com"
        ):
            obj = auth.UserPasswordAuth.load({})

        assert obj == auth.UserPasswordAuth("user-2@example.com", "P@ssw0rd")

    @pytest.mark.usefixtures("_unfreeze")
    def test_load_missing(self, caplog: pytest.LogCaptureFixture):
        with caplog.at_level(logging.ERROR):
            assert auth.UserPasswordAuth.load({}) is None
            assert "Missing auth information: username." in caplog.text

        with caplog.at_level(logging.ERROR):
            obj = auth.UserPasswordAuth.load({"username": "user-1@example.com"})
            assert obj is None
            assert "Missing auth information: password" in caplog.text


class TestOktaAuth:
    def setup_method(self):
        self.obj = auth.OktaAuth("user", "pass")

    def test__init__(self):
        assert self.obj.username == "user"
        assert self.obj.password == "pass"

    def test__repr__(self):
        assert repr(self.obj) == "OktaAuth(username='user')"

    def test_method(self):
        assert auth.OktaAuth.method() == "okta"

    def test_apply(self):
        client = Mock(spec=hvac.Client)

        self.obj.apply(client)
        assert client.auth.okta.login.call_count == 1

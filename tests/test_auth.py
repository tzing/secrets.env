from unittest.mock import Mock, patch

import hvac
import pytest

from secrets_env import auth


class TestAuth:
    def setup_method(self):
        self.client = Mock(spec=hvac.Client)

        self.patcher = patch("keyring.get_password", return_value=None)
        self.keyring = self.patcher.start()

    def teardown_method(self):
        self.patcher.stop()

    def test_token_auth(self):
        # success
        obj = auth.TokenAuth("Token")
        assert obj.method == "token"
        assert obj.token == "Token"

        # fail
        with pytest.raises(TypeError):
            auth.TokenAuth(1234)

        # apply
        obj.apply(self.client)
        assert self.client.token == "Token"

        # create
        assert auth.TokenAuth.load({}) is None

        with patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "foo"}):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

        self.keyring.return_value = "Token"
        assert auth.TokenAuth.load({}) == auth.TokenAuth("Token")

    def test_okta_auth(self):
        # success
        obj = auth.OktaAuth("User", "P@ssw0rd")
        assert obj.method == "okta"
        assert obj.username == "User"
        assert obj.password == "P@ssw0rd"

        # fail
        with pytest.raises(TypeError):
            auth.OktaAuth(1234, "P@ssw0rd")
        with pytest.raises(TypeError):
            auth.OktaAuth("User", 1234)

        # apply
        obj.apply(self.client)
        assert self.client.auth.okta.login.call_count == 1

        # create
        with patch.dict(
            "os.environ", {"SECRETS_ENV_USERNAME": "foo", "SECRETS_ENV_PASSWORD": "bar"}
        ):
            assert auth.OktaAuth.load({}) == auth.OktaAuth("foo", "bar")

        with patch.dict("os.environ", {"SECRETS_ENV_USERNAME": "foo"}):
            assert auth.OktaAuth.load({}) is None
        with patch.dict("os.environ", {"SECRETS_ENV_PASSWORD": "bar"}):
            assert auth.OktaAuth.load({}) is None

        self.keyring.side_effect = ["test@example.com", "P@ssw0rd"]
        assert auth.OktaAuth.load({}) == auth.OktaAuth("test@example.com", "P@ssw0rd")

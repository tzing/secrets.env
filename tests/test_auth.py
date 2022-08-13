from unittest.mock import Mock, patch

import hvac
import pytest

from secrets_env import auth


class TestAuth:
    @pytest.fixture()
    def get_password(self):
        with patch("secrets_env.auth.get_password", return_value=None) as kr:
            yield kr

    def setup_method(self):
        self.client = Mock(spec=hvac.Client)

    def test_token_auth(self, get_password: Mock):
        # success
        obj = auth.TokenAuth("Token")
        assert obj.method() == "token"
        assert obj.token == "Token"

        # fail
        with pytest.raises(TypeError):
            auth.TokenAuth(1234)

        # apply
        obj.apply(self.client)
        assert self.client.token == "Token"

        # create
        assert auth.TokenAuth.load({}) is None

        with patch.dict("os.environ", {"VAULT_TOKEN": "foo"}):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

        get_password.return_value = "Token"
        assert auth.TokenAuth.load({}) == auth.TokenAuth("Token")

    def test_okta_auth(self, get_password: Mock):
        # success
        obj = auth.OktaAuth("User", "P@ssw0rd")
        assert obj.method() == "okta"
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
            "os.environ", {"VAULT_USERNAME": "foo", "VAULT_PASSWORD": "bar"}
        ):
            assert auth.OktaAuth.load({}) == auth.OktaAuth("foo", "bar")

        with patch.dict("os.environ", {"VAULT_USERNAME": "foo"}):
            assert auth.OktaAuth.load({}) is None
        with patch.dict("os.environ", {"VAULT_PASSWORD": "bar"}):
            assert auth.OktaAuth.load({}) is None

        get_password.side_effect = ["test@example.com", "P@ssw0rd"]
        assert auth.OktaAuth.load({}) == auth.OktaAuth("test@example.com", "P@ssw0rd")

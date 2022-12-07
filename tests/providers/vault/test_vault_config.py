from unittest.mock import Mock

import pytest

import secrets_env.providers.vault.config as t
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.null import NoAuth


class TestGetURL:
    def setup_method(self):
        self.data = {"url": "https://data.example.com"}

    def test_from_data(self):
        assert t.get_url(self.data) == "https://data.example.com"

    @pytest.mark.parametrize("var_name", ["SECRETS_ENV_ADDR", "VAULT_ADDR"])
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch, var_name: str):
        monkeypatch.setenv(var_name, "https://env.example.com")
        assert t.get_url(self.data) == "https://env.example.com"

    def test_missing(self, caplog: pytest.LogCaptureFixture):
        assert t.get_url({}) is None
        assert "Missing required config <mark>url</mark>." in caplog.text

    def test_type_error(self):
        assert t.get_url({"url": 1234}) is None


class TestGetAuthBehavior:
    def test_from_data(self):
        assert isinstance(t.get_auth({"method": "null"}), NoAuth)

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "null")
        assert isinstance(t.get_auth({}), NoAuth)

    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("null"), NoAuth)

    def test_type_error(self):
        assert t.get_auth({"method": 1234}) is None

    def test_default_method(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setattr(t, "DEFAULT_AUTH_METHOD", "null")

        assert isinstance(t.get_auth({}), NoAuth)
        assert (
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>null</data>"
        ) in caplog.text

    def test_unknown_method(self, caplog: pytest.LogCaptureFixture):
        assert t.get_auth({"method": "no-this-method"}) is None
        assert "Unknown auth method: <data>no-this-method</data>" in caplog.text


class TestGetAuthFactory:
    def setup_method(self):
        self.mock_auth = Mock(spec=Auth)

    def mock_load(self, data: dict) -> Auth:
        assert isinstance(data, dict)
        return self.mock_auth

    def test_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.token.TokenAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "TOKEN"}) is self.mock_auth

    def test_okta(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.OktaAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "okta"}) is self.mock_auth

    def test_oidc(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.oidc.OpenIDConnectAuth.load",
            self.mock_load,
        )
        assert t.get_auth({"method": "oidc"}) is self.mock_auth

    def test_no_auth(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.null.NoAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "null"}) is self.mock_auth

    def test_basic(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.BasicAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "Basic"}) is self.mock_auth

    def test_ldap(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.LDAPAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "LDAP"}) is self.mock_auth

    def test_radius(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.RADIUSAuth.load", self.mock_load
        )
        assert t.get_auth({"method": "radius"}) is self.mock_auth

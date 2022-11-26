from unittest.mock import Mock

import pytest

from secrets_env.auth import get_auth
from secrets_env.auth.base import Auth


class TestGetAuth:
    def setup_method(self):
        self.mock_auth = Mock(spec=Auth)

    def mock_load(self, data: dict) -> Auth:
        assert isinstance(data, dict)
        return self.mock_auth

    def test_fail(self, caplog: pytest.LogCaptureFixture):
        assert get_auth("no-this-method", {}) is None
        assert "Unknown auth method: <data>no-this-method</data>" in caplog.text

    def test_success_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.token.TokenAuth.load", self.mock_load)
        assert get_auth("TOKEN", {}) is self.mock_auth

    def test_success_okta(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.userpass.OktaAuth.load", self.mock_load)
        assert get_auth("okta", {}) is self.mock_auth

    def test_success_oidc(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.auth.oidc.OpenIDConnectAuth.load", self.mock_load
        )
        assert get_auth("oidc", {}) is self.mock_auth

    def test_success_no_auth(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.null.NoAuth.load", self.mock_load)
        assert get_auth("null", {}) is self.mock_auth

    def test_success_basic(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.userpass.BasicAuth.load", self.mock_load)
        assert get_auth("Basic", {}) is self.mock_auth

    def test_success_ldap(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.userpass.LDAPAuth.load", self.mock_load)
        assert get_auth("LDAP", {}) is self.mock_auth

    def test_success_radius(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("secrets_env.auth.userpass.RADIUSAuth.load", self.mock_load)
        assert get_auth("radius", {}) is self.mock_auth

from unittest.mock import Mock

import httpx
import pytest
from pydantic_core import Url, ValidationError

from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.providers.vault.auth.base import Auth, NoAuth
from secrets_env.providers.vault.auth.token import TokenAuth


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("ldap", "secrets_env.providers.vault.auth.userpass.LDAPAuth.create"),
        ("null", "secrets_env.providers.vault.auth.base.NoAuth.create"),
        ("oidc", "secrets_env.providers.vault.auth.oidc.OpenIDConnectAuth.create"),
        ("okta", "secrets_env.providers.vault.auth.userpass.OktaAuth.create"),
        ("radius", "secrets_env.providers.vault.auth.userpass.RADIUSAuth.create"),
        ("token", "secrets_env.providers.vault.auth.token.TokenAuth.create"),
        ("userpass", "secrets_env.providers.vault.auth.userpass.UserPassAuth.create"),
    ],
)
def test_create_auth_by_name(monkeypatch: pytest.MonkeyPatch, method: str, path: str):
    monkeypatch.setattr(path, lambda url, config: Mock(Auth))
    auth = create_auth_by_name(Url("https://example.com/"), {"method": method})
    assert isinstance(auth, Auth)


def test_create_auth_by_name_fail():
    with pytest.raises(ValueError, match="Unknown auth method: invalid"):
        create_auth_by_name(Url("https://example.com/"), {"method": "invalid"})


class TestNoAuth:
    def test_login(self):
        auth = NoAuth()
        assert auth.login(Mock()) == ""

        auth = NoAuth(token="test")
        assert auth.login(Mock()) == "test"

    def test_create(self):
        assert isinstance(NoAuth.create(Url("https://example.com/"), {}), NoAuth)


class TestTokenAuth:
    def test_create_from_envvar(self, monkeypatch: pytest.MonkeyPatch):
        sample = TokenAuth(token="T0ken")

        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_TOKEN", "T0ken")
            assert TokenAuth.create(Url("https://example.com/"), {}) == sample

        with monkeypatch.context() as m:
            m.setenv("VAULT_TOKEN", "T0ken")
            assert TokenAuth.create(Url("https://example.com/"), {}) == sample

    def test_create_failed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("VAULT_TOKEN", False)
        with pytest.raises(ValidationError, match="Input should be a valid string."):
            assert TokenAuth.create(Url("https://example.com/"), {}) is None

    def test_login(self):
        client = Mock(spec=httpx.Client)
        sample = TokenAuth(token="T0ken")
        assert sample.login(client) == "T0ken"

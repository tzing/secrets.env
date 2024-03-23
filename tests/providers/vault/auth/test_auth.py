from unittest.mock import Mock

import pytest
from pydantic_core import Url

from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.providers.vault.auth.base import Auth, NoAuth


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

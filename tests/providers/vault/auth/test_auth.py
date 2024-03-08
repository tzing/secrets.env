from unittest.mock import Mock

import pytest

from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.providers.vault.auth.base import Auth, NullAuth


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("basic", "secrets_env.providers.vault.auth.userpass.BasicAuth.create"),
        ("ldap", "secrets_env.providers.vault.auth.userpass.LDAPAuth.create"),
        ("null", "secrets_env.providers.vault.auth.base.NullAuth.create"),
        ("oidc", "secrets_env.providers.vault.auth.oidc.OpenIDConnectAuth.create"),
        ("okta", "secrets_env.providers.vault.auth.userpass.OktaAuth.create"),
        ("radius", "secrets_env.providers.vault.auth.userpass.RADIUSAuth.create"),
        ("token", "secrets_env.providers.vault.auth.token.TokenAuth.create"),
    ],
)
def test_create_auth_by_name(monkeypatch: pytest.MonkeyPatch, method: str, path: str):
    monkeypatch.setattr(path, lambda url, config: Mock(Auth))
    auth = create_auth_by_name("https://example.com/", {"method": method})
    assert isinstance(auth, Auth)


def test_create_auth_by_name_fail():
    with pytest.raises(ValueError, match="Unknown auth method: invalid"):
        create_auth_by_name("https://example.com/", {"method": "invalid"})


class TestNullAuth:
    def test_login(self):
        auth = NullAuth()
        assert auth.login(object()) is None

    def test_create(self):
        assert isinstance(NullAuth.create("https://example.com/", {}), NullAuth)

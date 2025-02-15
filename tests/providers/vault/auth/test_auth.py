from unittest.mock import Mock

import pytest
from pydantic_core import Url

from secrets_env.providers.vault.auth import create_auth
from secrets_env.providers.vault.auth.base import Auth, NoAuth


class TestCreateAuth:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            (
                "kubernetes",
                "secrets_env.providers.vault.auth.kubernetes.KubernetesAuth.create",
            ),
            ("ldap", "secrets_env.providers.vault.auth.userpass.LdapAuth.create"),
            ("null", "secrets_env.providers.vault.auth.base.NoAuth.create"),
            ("oidc", "secrets_env.providers.vault.auth.oidc.OpenIDConnectAuth.create"),
            ("okta", "secrets_env.providers.vault.auth.userpass.OktaAuth.create"),
            ("radius", "secrets_env.providers.vault.auth.userpass.RadiusAuth.create"),
            ("token", "secrets_env.providers.vault.auth.token.TokenAuth.create"),
            (
                "userpass",
                "secrets_env.providers.vault.auth.userpass.UserPassAuth.create",
            ),
        ],
    )
    def test(self, monkeypatch: pytest.MonkeyPatch, method: str, path: str):
        monkeypatch.setattr(path, lambda url, config: Mock(Auth))
        auth = create_auth(url=Url("https://example.com/"), method=method)
        assert isinstance(auth, Auth)

    def test_fail(self):
        with pytest.raises(ValueError, match="Unknown auth method: invalid"):
            create_auth(url=Url("https://example.com/"), method="invalid")


class TestNoAuth:
    def test_login(self):
        auth = NoAuth()
        assert auth.login(Mock()) == ""

        auth = NoAuth(token="test")
        assert auth.login(Mock()) == "test"

    def test_create(self):
        assert isinstance(NoAuth.create(Url("https://example.com/"), {}), NoAuth)

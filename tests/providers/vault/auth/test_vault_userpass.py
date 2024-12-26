import re
from unittest.mock import Mock

import httpx
import pytest
import respx
from pydantic import HttpUrl

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.userpass import (
    LdapAuth,
    OktaAuth,
    RadiusAuth,
    UserPassAuth,
    UserPasswordAuth,
    get_password,
    get_username,
)


@pytest.fixture
def login_success_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": None,
            "warnings": None,
            "auth": {
                "client_token": "client-token",
                "accessor": "accessor-token",
                "policies": ["default"],
                "metadata": {"username": "fred", "policies": "default"},
                "lease_duration": 7200,
                "renewable": True,
            },
        },
    )


class TestUserPasswordAuth:

    def test_create_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.get_username",
            lambda _1, _2: "user",
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.get_password",
            lambda _1, _2: "P@ssw0rd",
        )

        obj = UserPasswordAuth.create(HttpUrl("https://example.com/"), {})
        assert obj == UserPasswordAuth(username="user", password="P@ssw0rd")

    @pytest.mark.parametrize(
        ("username", "password", "err_message"),
        [
            ("user@example.com", "", "Missing password for MOCK auth"),
            ("", "P@ssw0rd", "Missing username for MOCK auth"),
            ("user@example.com", None, "Missing password for MOCK auth"),
            (None, "P@ssw0rd", "Missing username for MOCK auth"),
        ],
    )
    def test_load_fail(
        self,
        monkeypatch: pytest.MonkeyPatch,
        username: str,
        password: str,
        err_message: str,
    ):
        class MockAuth(UserPasswordAuth):
            method = "MOCK"

        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.get_username",
            lambda _1, _2: username,
        )
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.get_password",
            lambda _1, _2: password,
        )

        with pytest.raises(ValueError, match=re.escape(err_message)):
            assert MockAuth.create(HttpUrl("https://example.com/"), {}) is None

    def test_login_success(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/mock/login/user%40example.com").mock(
            return_value=login_success_response
        )

        class MockAuth(UserPasswordAuth):
            method = "MOCK"
            vault_name = "mock"

        auth_obj = MockAuth(username="user@example.com", password="password")
        assert auth_obj.login(unittest_client) == "client-token"

    def test_login_fail(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/mock/login/user%40example.com").mock(
            return_value=httpx.Response(400)
        )

        class MockAuth(UserPasswordAuth):
            method = "MOCK"
            vault_name = "mock"

        auth_obj = MockAuth(username="user@example.com", password="password")

        with pytest.raises(AuthenticationError):
            assert auth_obj.login(unittest_client) is None


class TestGetUsername:

    def test_config(self):
        assert (
            get_username(HttpUrl("https://example.com/"), {"username": "foo"}) == "foo"
        )

    def test_env_var(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "foo")
        assert get_username(HttpUrl("https://example.com/"), {}) == "foo"

    def test_user_config(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.load_user_config",
            lambda _: {"auth": {"username": "foo"}},
        )
        assert get_username(HttpUrl("https://example.com/"), {}) == "foo"

    def test_prompt(self, monkeypatch: pytest.MonkeyPatch):
        mock_prompt = Mock(return_value="foo")
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.prompt", mock_prompt
        )

        assert get_username(HttpUrl("https://example.com/"), {}) == "foo"
        mock_prompt.assert_any_call("Username for example.com")

    def test__load_username(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.load_user_config",
            lambda _: {},
        )

        mock_prompt = Mock(return_value="foo")
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.prompt", mock_prompt
        )

        assert get_username(HttpUrl("https://example.com/"), {}) == "foo"
        mock_prompt.assert_called_once_with("Username for example.com")


class TestGetPassword:

    def test_env_var(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "bar")
        assert get_password(HttpUrl("https://example.com/"), "foo") == "bar"

    def test_keyring(self, monkeypatch: pytest.MonkeyPatch):
        mock_read_keyring = Mock(return_value="bar")
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.read_keyring", mock_read_keyring
        )

        assert get_password(HttpUrl("https://example.com/"), "foo") == "bar"
        mock_read_keyring.assert_any_call(
            '{"host": "example.com", "type": "login", "user": "foo"}'
        )

    def test_prompt(self, monkeypatch: pytest.MonkeyPatch):
        mock_prompt = Mock(return_value="bar")
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.userpass.prompt", mock_prompt
        )

        assert get_password(HttpUrl("https://example.com/"), "foo") == "bar"
        mock_prompt.assert_called_once_with("Password for foo", hide_input=True)


@pytest.mark.parametrize(
    ("method_class", "login_path"),
    [
        (LdapAuth, "/v1/auth/ldap/login/user"),
        (OktaAuth, "/v1/auth/okta/login/user"),
        (RadiusAuth, "/v1/auth/radius/login/user"),
        (UserPassAuth, "/v1/auth/userpass/login/user"),
    ],
)
def test_auth_methods(
    monkeypatch: pytest.MonkeyPatch,
    method_class: type[UserPasswordAuth],
    unittest_respx: respx.MockRouter,
    login_path: str,
    login_success_response: httpx.Response,
    unittest_client: httpx.Client,
):
    # no exception is enough
    assert isinstance(method_class.method, str)

    # test creation
    monkeypatch.setenv("SECRETS_ENV_USERNAME", "user")
    monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")

    auth = method_class.create(HttpUrl("https://example.com/"), {})
    assert auth

    # test login
    unittest_respx.post(login_path).mock(return_value=login_success_response)

    assert auth.login(unittest_client) == "client-token"

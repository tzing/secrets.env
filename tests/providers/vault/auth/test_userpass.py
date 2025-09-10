import re
from unittest.mock import Mock

import pytest
import respx
from httpx import AsyncClient, Response
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
def login_success_response() -> Response:
    return Response(
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

    @pytest.fixture
    def route(self, respx_mock: respx.MockRouter) -> respx.Route:
        return respx_mock.post(
            "https://example.com/v1/auth/mock/login/user%40example.com"
        )

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
        assert obj == UserPasswordAuth.model_validate(
            {"username": "user", "password": "P@ssw0rd"}
        )

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

    @pytest.mark.asyncio
    async def test_login_success(
        self, route: respx.Route, login_success_response: Response
    ):
        route.mock(return_value=login_success_response)

        class MockAuth(UserPasswordAuth):
            method = "MOCK"
            vault_name = "mock"

        auth = MockAuth.model_validate(
            {"username": "user@example.com", "password": "password"}
        )
        client = AsyncClient(base_url="https://example.com")
        assert await auth.login(client) == "client-token"

    @pytest.mark.asyncio
    async def test_login_fail(self, route: respx.Route):
        route.mock(return_value=Response(400))

        class MockAuth(UserPasswordAuth):
            method = "MOCK"
            vault_name = "mock"

        auth = MockAuth.model_validate(
            {"username": "user@example.com", "password": "password"}
        )
        client = AsyncClient(base_url="https://example.com")

        with pytest.raises(AuthenticationError):
            await auth.login(client)


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_class", "login_path"),
    [
        (LdapAuth, "/v1/auth/ldap/login/user"),
        (OktaAuth, "/v1/auth/okta/login/user"),
        (RadiusAuth, "/v1/auth/radius/login/user"),
        (UserPassAuth, "/v1/auth/userpass/login/user"),
    ],
)
async def test_auth_methods(
    monkeypatch: pytest.MonkeyPatch,
    method_class: type[UserPasswordAuth],
    login_path: str,
    login_success_response: Response,
):
    # no exception is enough
    assert isinstance(method_class.method, str)

    # test creation
    monkeypatch.setenv("SECRETS_ENV_USERNAME", "user")
    monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")

    auth = method_class.create(HttpUrl("https://example.com/"), {})
    assert auth

    # test login
    client = AsyncClient(base_url="https://example.com")

    with respx.mock(base_url="https://example.com") as r:
        r.post(login_path).mock(return_value=login_success_response)
        assert await auth.login(client) == "client-token"

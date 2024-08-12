import re
from typing import Type
from unittest.mock import patch

import httpx
import pytest
import respx
from pydantic_core import Url

import secrets_env.providers.vault.auth.userpass as t
from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.userpass import UserPasswordAuth


@pytest.fixture()
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
        monkeypatch.setattr(UserPasswordAuth, "_get_username", lambda _1, _2: "user")
        monkeypatch.setattr(
            UserPasswordAuth, "_get_password", lambda _1, _2: "P@ssw0rd"
        )

        obj = UserPasswordAuth.create(Url("https://example.com/"), {})
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

        monkeypatch.setattr(MockAuth, "_get_username", lambda _1, _2: username)
        monkeypatch.setattr(MockAuth, "_get_password", lambda _1, _2: password)

        with pytest.raises(ValueError, match=re.escape(err_message)):
            assert MockAuth.create(Url("https://example.com/"), {}) is None

    def test__load_username(self, monkeypatch: pytest.MonkeyPatch):
        class MockAuth(UserPasswordAuth):
            method = "MOCK"

        url = Url("https://example.com/")

        # config
        assert MockAuth._get_username({"username": "foo"}, url) == "foo"

        # env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_USERNAME", "foo")
            assert MockAuth._get_username({}, url) == "foo"

        # user config
        with patch.object(
            t, "load_user_config", return_value={"auth": {"username": "foo"}}
        ):
            assert MockAuth._get_username({}, url) == "foo"

        # prompt
        with (
            patch.object(t, "load_user_config", return_value={}),
            patch.object(t, "prompt", return_value="foo") as p,
        ):
            assert MockAuth._get_username({}, url) == "foo"
            p.assert_any_call("Username for MOCK auth")

    def test__load_password(self, monkeypatch: pytest.MonkeyPatch):
        # env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_PASSWORD", "bar")
            out = UserPasswordAuth._get_password(Url("https://example.com/"), "foo")
            assert out == "bar"

        # prompt
        with patch.object(t, "prompt", return_value="bar") as p:
            out = UserPasswordAuth._get_password(Url("https://example.com/"), "foo")
            assert out == "bar"
            p.assert_any_call("Password for foo", hide_input=True)

        # keyring
        with patch.object(t, "read_keyring", return_value="bar") as r:
            out = UserPasswordAuth._get_password(Url("https://example.com/"), "foo")
            assert out == "bar"
            r.assert_any_call('{"host": "example.com", "type": "login", "user": "foo"}')

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


@pytest.mark.parametrize(
    ("method_class", "login_path"),
    [
        (t.LDAPAuth, "/v1/auth/ldap/login/user"),
        (t.OktaAuth, "/v1/auth/okta/login/user"),
        (t.RADIUSAuth, "/v1/auth/radius/login/user"),
        (t.UserPassAuth, "/v1/auth/userpass/login/user"),
    ],
)
def test_auth_methods(
    monkeypatch: pytest.MonkeyPatch,
    method_class: Type[UserPasswordAuth],
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

    auth = method_class.create(Url("https://example.com/"), {})
    assert auth

    # test login
    unittest_respx.post(login_path).mock(return_value=login_success_response)

    assert auth.login(unittest_client) == "client-token"

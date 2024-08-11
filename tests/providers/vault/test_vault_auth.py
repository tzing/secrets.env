import re
import threading
from typing import Type
from unittest.mock import Mock, patch

import httpx
import pytest
import respx
from pydantic_core import Url, ValidationError

import secrets_env.providers.vault.auth.oidc as t
import secrets_env.server
from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.providers.vault.auth.base import Auth, NoAuth
from secrets_env.providers.vault.auth.oidc import (
    OIDCRequestHandler,
    OpenIDConnectAuth,
    get_authorization_url,
    request_token,
)
from secrets_env.providers.vault.auth.token import TokenAuth
from secrets_env.providers.vault.auth.userpass import (
    LDAPAuth,
    OktaAuth,
    RADIUSAuth,
    UserPassAuth,
    UserPasswordAuth,
)


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


class TestUserPasswordAuth:
    def test_create(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            UserPasswordAuth,
            "_get_username",
            lambda _1, _2: "user",
        )
        monkeypatch.setattr(
            UserPasswordAuth,
            "_get_password",
            lambda _1, _2: "P@ssw0rd",
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
    def test_missing_value(self, username: str, password: str, err_message: str):
        class MockAuth(UserPasswordAuth):
            method = "MOCK"

            @classmethod
            def _get_username(cls, config, url):
                return username

            @classmethod
            def _get_password(cls, url, username):
                return password

        with pytest.raises(ValueError, match=re.escape(err_message)):
            assert MockAuth.create(Url("https://example.com/"), {}) is None

    def test__get_username(self, monkeypatch: pytest.MonkeyPatch):
        import secrets_env.providers.vault.auth.userpass as module

        class MockAuth(UserPasswordAuth):
            method = "MOCK"

        url = Url("https://example.com/")

        # from config
        assert MockAuth._get_username({"username": "foo"}, url) == "foo"

        # from env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_USERNAME", "foo")
            assert MockAuth._get_username({}, url) == "foo"

        # from user config
        with patch.object(
            module,
            "load_user_config",
            return_value={"auth": {"username": "foo"}},
        ):
            assert MockAuth._get_username({}, url) == "foo"

        # from prompt
        with (
            patch.object(module, "load_user_config", return_value={}),
            patch.object(module, "prompt", return_value="foo") as mock_prompt,
        ):
            assert MockAuth._get_username({}, url) == "foo"
        mock_prompt.assert_any_call("Username for MOCK auth")

    def test__get_password(self, monkeypatch: pytest.MonkeyPatch):
        import secrets_env.providers.vault.auth.userpass as module

        def _get_password():
            return UserPasswordAuth._get_password(Url("https://example.com/"), "foo")

        # from env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_PASSWORD", "bar")
            assert _get_password() == "bar"

        # from prompt
        with patch.object(module, "prompt", return_value="bar") as mock_prompt:
            assert _get_password() == "bar"
        mock_prompt.assert_any_call("Password for foo", hide_input=True)

        # from keyring
        with patch.object(module, "read_keyring", return_value="bar") as mock_read:
            assert _get_password() == "bar"
        mock_read.assert_any_call(
            '{"host": "example.com", "type": "login", "user": "foo"}'
        )

    def test_login_success(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/mock/login/user%40example.com").mock(
            return_value=httpx.Response(
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


class TestUserPasswordAuthChild:
    @pytest.mark.parametrize(
        ("method_class", "login_path"),
        [
            (LDAPAuth, "/v1/auth/ldap/login/user"),
            (OktaAuth, "/v1/auth/okta/login/user"),
            (RADIUSAuth, "/v1/auth/radius/login/user"),
            (UserPassAuth, "/v1/auth/userpass/login/user"),
        ],
    )
    def test(
        self,
        monkeypatch: pytest.MonkeyPatch,
        method_class: Type[UserPasswordAuth],
        unittest_respx: respx.MockRouter,
        login_path: str,
        unittest_client: httpx.Client,
    ):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "user")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")

        assert isinstance(method_class.method, str)

        auth = method_class.create(Url("https://example.com/"), {})
        assert isinstance(auth, UserPasswordAuth)

        unittest_respx.post(login_path).mock(
            return_value=httpx.Response(
                200,
                json={
                    "auth": {
                        "client_token": "test-token",
                    },
                },
            )
        )
        assert auth.login(unittest_client) == "test-token"


class TestOpenIDConnectAuth:
    def test_create__default(self):
        auth = OpenIDConnectAuth.create(Url("https://example.com/"), {})
        assert isinstance(auth, OpenIDConnectAuth)
        assert auth.role is None

    def test_create__envvar(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ROLE", "demo")
        auth = OpenIDConnectAuth.create(Url("https://example.com/"), {})
        assert isinstance(auth, OpenIDConnectAuth)
        assert auth.role == "demo"

    def test_create__config(self):
        auth = OpenIDConnectAuth.create(Url("https://example.com/"), {"role": "sample"})
        assert isinstance(auth, OpenIDConnectAuth)
        assert auth.role == "sample"

    @pytest.fixture()
    def _patch_get_authorization_url(self, monkeypatch: pytest.MonkeyPatch):
        def mock_get_authorization_url(client, redirect_uri, role, client_nonce):
            assert isinstance(client, httpx.Client)
            assert re.fullmatch(r"http://127\.0\.0\.1:\d+/oidc/callback", redirect_uri)
            assert isinstance(role, str) or role is None
            assert isinstance(client_nonce, str)
            return "https://example.com/auth"

        monkeypatch.setattr(t, "get_authorization_url", mock_get_authorization_url)

    @pytest.fixture()
    def patch_start_server(self, monkeypatch: pytest.MonkeyPatch):
        # don't start server
        server = Mock(
            spec=secrets_env.server.ThreadingHTTPServer,
            server_uri="http://127.0.0.1:0000",
            ready=Mock(spec=threading.Event),
            context={},
            server_thread=Mock(spec=threading.Thread),
        )

        def patch_start_server(handler, ready):
            return server

        monkeypatch.setattr(t, "start_server", patch_start_server)
        return server

    @pytest.mark.usefixtures("_patch_get_authorization_url")
    def test_login_success(self, monkeypatch: pytest.MonkeyPatch, patch_start_server):
        # patch webbrowser.open for simulates callback result
        def patch_webbrowser_open(entrypoint):
            assert entrypoint.startswith("http://127.0.0.1:")
            patch_start_server.context["token"] = "t0ken"

        monkeypatch.setattr("webbrowser.open", patch_webbrowser_open)

        # run
        auth = OpenIDConnectAuth(role=None)
        assert auth.login(Mock(spec=httpx.Client)) == "t0ken"

    def test_login_fail_1(self, monkeypatch: pytest.MonkeyPatch):
        # case: get auth url failed
        monkeypatch.setattr(t, "get_authorization_url", lambda *_: None)
        auth = OpenIDConnectAuth(role=None)
        with pytest.raises(AuthenticationError):
            auth.login(Mock(spec=httpx.Client))

    @pytest.mark.usefixtures("_patch_get_authorization_url", "patch_start_server")
    def test_login_fail_2(self, monkeypatch: pytest.MonkeyPatch):
        # case: not received the token
        monkeypatch.setattr("webbrowser.open", lambda _: None)
        auth = OpenIDConnectAuth(role=None)
        with pytest.raises(AuthenticationError):
            auth.login(Mock(spec=httpx.Client))


class TestOidcRequestHandler:
    def setup_method(self):
        self.server = secrets_env.server.start_server(OIDCRequestHandler)
        self.server.context.update(
            entrypoint="/ffff-ffff",
            client=Mock(spec=httpx.Client),
            auth_url="https://example.com/auth",
            client_nonce="0000-0000",
        )

        self.client = httpx.Client(base_url=self.server.server_uri)

    def teardown_method(self):
        self.server.shutdown()

    def test_do_forward_auth_url(self):
        resp = self.client.get("/ffff-ffff")
        assert resp.is_redirect
        assert resp.next_request.url == "https://example.com/auth"

    def test_do_oidc_callback_success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_request_token(client, auth_url, auth_code, client_nonce):
            return "t0ken"

        monkeypatch.setattr(t, "request_token", mock_request_token)

        resp = self.client.get("/oidc/callback?code=blah")
        assert resp.status_code == 200
        assert self.server.context["token"] == "t0ken"

        self.server.server_thread.join(1.0)
        assert not self.server.server_thread.is_alive()

    def test_do_oidc_callback_fail(self, monkeypatch: pytest.MonkeyPatch):
        self.server.context.update()

        # missing auth code
        resp = self.client.get("/oidc/callback")
        assert resp.status_code == 400

        # request token fail
        def mock_request_token(client, auth_url, auth_code, client_nonce): ...

        monkeypatch.setattr(t, "request_token", mock_request_token)
        resp = self.client.get("/oidc/callback?code=blah")
        assert resp.status_code == 500


class TestOidcGetAuthorizationUrl:
    def test_success(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/oidc/oidc/auth_url").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "d3a4b3df-efbe-e18e-65b1-b8fe372af0a9",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {"auth_url": "https://auth.example.com/"},
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert (
            get_authorization_url(
                unittest_client,
                "http://127.0.0.1/callback",
                None,
                "test-nonce",
            )
            == "https://auth.example.com/"
        )

    def test_fail(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/oidc/oidc/auth_url") % 403

        assert (
            get_authorization_url(
                unittest_client,
                "http://localhost/callback",
                "test_role",
                "test-nonce",
            )
            is None
        )


class TestOidcRequestToken:
    def test_success(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.get(
            "/v1/auth/oidc/oidc/callback",
            params={
                "state": "sample-state",
                "nonce": "sample-nonce",
                "code": "test-code",
                "client_nonce": "test-nonce",
            },
        ).mock(
            httpx.Response(
                200,
                json={
                    "request_id": "18ce3b76-50c8-a10d-6660-b6d1554a17c7",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": None,
                    "wrap_info": None,
                    "warnings": [],
                    "auth": {
                        "client_token": "sample-token",
                        "accessor": "sample-accessor",
                        "policies": ["default"],
                        "token_policies": ["default"],
                        "identity_policies": [],
                        "metadata": {"role": "default"},
                        "lease_duration": 3600,
                        "renewable": True,
                        "entity_id": "8731089d-55a2-5255-0d50-5fe539af9872",
                        "token_type": "service",
                        "orphan": True,
                        "mfa_requirement": None,
                        "num_uses": 0,
                    },
                },
            )
        )
        assert (
            request_token(
                unittest_client,
                "http://auth.example.com/?state=sample-state&nonce=sample-nonce",
                "test-code",
                "test-nonce",
            )
            == "sample-token"
        )

    def test_error(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.get("/v1/auth/oidc/oidc/callback") % 403
        assert (
            request_token(
                unittest_client,
                "http://auth.example.com/?state=sample-state&nonce=sample-nonce",
                "test-code",
                "test-nonce",
            )
            is None
        )

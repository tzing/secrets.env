import re
import threading
from unittest.mock import Mock

import httpx
import pytest
import respx
from pydantic_core import Url

import secrets_env.providers.vault.auth.oidc as t
from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.oidc import (
    OidcRequestHandler,
    OpenIDConnectAuth,
    get_authorization_url,
    request_token,
)
from secrets_env.realms.server import ThreadedHttpServer, start_server


class TestOpenIDConnectAuth:
    def test_create_default(self):
        auth = OpenIDConnectAuth.create(Url("https://example.com/"), {})
        assert isinstance(auth, OpenIDConnectAuth)
        assert auth.role is None

    def test_create_config(self):
        auth = OpenIDConnectAuth.create(Url("https://example.com/"), {"role": "sample"})
        assert isinstance(auth, OpenIDConnectAuth)
        assert auth.role == "sample"

    @pytest.fixture
    def _patch_get_authorization_url(self, monkeypatch: pytest.MonkeyPatch):
        def mock_get_authorization_url(client, redirect_uri, role, client_nonce):
            assert isinstance(client, httpx.Client)
            assert re.fullmatch(r"http://127\.0\.0\.1:\d+/oidc/callback", redirect_uri)
            assert isinstance(role, str) or role is None
            assert isinstance(client_nonce, str)
            return "https://example.com/auth"

        monkeypatch.setattr(t, "get_authorization_url", mock_get_authorization_url)

    @pytest.fixture
    def patch_start_server(self, monkeypatch: pytest.MonkeyPatch):
        # don't start server
        sever = Mock(
            spec=ThreadedHttpServer,
            server_uri="http://127.0.0.1:0000",
            ready=Mock(spec=threading.Event),
            context={},
            server_thread=Mock(spec=threading.Thread),
        )

        def patch_start_server(handler, ready):
            return sever

        monkeypatch.setattr(t, "start_server", patch_start_server)
        return sever

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
    @pytest.fixture
    def server(self):
        server = start_server(OidcRequestHandler)
        server.context.update(
            {
                "entrypoint": "/ffff-ffff",
                "client": Mock(httpx.Client),
                "auth_url": "https://example.com/auth",
                "client_nonce": "0000-0000",
            }
        )

        yield server

        server.shutdown()

    @pytest.fixture
    def client(self, server: ThreadedHttpServer):
        return httpx.Client(base_url=server.server_url)

    def test_do_forward_auth_url(self, client: httpx.Client):
        resp = client.get("/ffff-ffff")
        assert resp.is_redirect
        assert resp.next_request.url == "https://example.com/auth"

    def test_do_oidc_callback_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        server: ThreadedHttpServer,
        client: httpx.Client,
    ):
        def mock_request_token(client, auth_url, auth_code, client_nonce):
            return "t0ken"

        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.oidc.request_token", mock_request_token
        )

        resp = client.get("/oidc/callback?code=blah")
        assert resp.status_code == 200
        assert server.context["token"] == "t0ken"

        server.server_thread.join(1.0)
        assert not server.server_thread.is_alive()

    def test_do_oidc_callback_fail(
        self, monkeypatch: pytest.MonkeyPatch, client: httpx.Client
    ):
        # missing auth code
        resp = client.get("/oidc/callback")
        assert resp.status_code == 400

        # request token fail
        monkeypatch.setattr(
            "secrets_env.providers.vault.auth.oidc.request_token",
            Mock(return_value=None),
        )
        resp = client.get("/oidc/callback?code=blah")
        assert resp.status_code == 500


class TestGetAuthorizationUrl:
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


class TestRequestToken:
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

import threading
import time
from http import HTTPStatus
from typing import Optional
from unittest.mock import Mock

import httpx
import pytest
import respx

import secrets_env.providers.vault.auth.oidc as t
from secrets_env.exceptions import AuthenticationError
from secrets_env.server import start_server


class TestOpenIDConnectAuth:
    def test___init__(self):
        # success
        t.OpenIDConnectAuth("default")
        t.OpenIDConnectAuth(None)

        # fail
        with pytest.raises(TypeError):
            t.OpenIDConnectAuth(1234)

    def test_method(self):
        assert isinstance(t.OpenIDConnectAuth.method(), str)

    def test_login_success(self, monkeypatch: pytest.MonkeyPatch):
        # NOTE this function simulates server callback

        # setup: control server port
        def patch_start_server(handler, ready):
            return start_server(handler, port=56789, ready=ready)

        monkeypatch.setattr(t, "start_server", patch_start_server)

        # setup: patch webbrowser.open for simulates callback
        def patch_webbrowser_open(url):
            assert url.startswith("http://127.0.0.1:56789/")
            httpx.get("http://127.0.0.1:56789/oidc/callback", params={"code": "test"})

        monkeypatch.setattr("webbrowser.open", patch_webbrowser_open)

        # setup: patch get_authorization_url
        def mock_get_authorization_url(client, redirect_uri, role, client_nonce):
            assert isinstance(client, httpx.Client)
            assert redirect_uri == "http://127.0.0.1:56789/oidc/callback"
            assert isinstance(role, str) or role is None
            assert isinstance(client_nonce, str)
            return "https://example.com/auth"

        monkeypatch.setattr(t, "get_authorization_url", mock_get_authorization_url)

        # setup: patch request_token
        def patch_request_token(client, auth_url, auth_code, client_nonce):
            assert isinstance(client, httpx.Client)
            assert auth_url == "https://example.com/auth"
            assert auth_code == "test"
            assert isinstance(client_nonce, str)
            return "t0ken"

        monkeypatch.setattr(t, "request_token", patch_request_token)

        # run
        client = Mock(spec=httpx.Client)

        auth = t.OpenIDConnectAuth()
        assert auth.login(client) == "t0ken"


#     def test_login_error_1(self, monkeypatch: pytest.MonkeyPatch):
#         # Failed to get auth URL
#         monkeypatch.setattr(t, "get_authorization_url", lambda *_: None)
#         with pytest.raises(AuthenticationError):
#             self.auth.login(self.client)

#     def test_login_error_2(self, monkeypatch: pytest.MonkeyPatch):
#         # Failed to get auth code
#         monkeypatch.setattr(
#             t, "get_authorization_url", lambda *_: "https://auth.example.com"
#         )
#         monkeypatch.setattr(
#             t, "OpenIDConnectCallbackService", Mock(spec=t.OpenIDConnectCallbackService)
#         )
#         monkeypatch.setattr("webbrowser.open", lambda _: None)

#         with pytest.raises(AuthenticationError):
#             self.auth.login(self.client)

#     def test_login_error_3(self, monkeypatch: pytest.MonkeyPatch):
#         # Failed to get client token
#         monkeypatch.setattr(
#             t, "get_authorization_url", lambda *_: "https://auth.example.com"
#         )
#         monkeypatch.setattr(
#             t, "OpenIDConnectCallbackService", Mock(spec=t.OpenIDConnectCallbackService)
#         )

#         def mock_open(url):
#             object.__setattr__(self.auth, "authorization_code", "auth-code")

#         monkeypatch.setattr("webbrowser.open", mock_open)
#         monkeypatch.setattr(t, "request_token", lambda *_: None)

#         with pytest.raises(AuthenticationError):
#             self.auth.login(self.client)


class TestOpenIDConnectAuthLoad:
    def test_load_default(self):
        auth = t.OpenIDConnectAuth.load({})
        assert isinstance(auth, t.OpenIDConnectAuth)
        assert auth.role is None

    def test_load_envvar(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_ROLE", "test")
        auth = t.OpenIDConnectAuth.load({})
        assert isinstance(auth, t.OpenIDConnectAuth)
        assert auth.role == "test"

    def test_load_config(self):
        auth = t.OpenIDConnectAuth.load({"role": "test"})
        assert isinstance(auth, t.OpenIDConnectAuth)
        assert auth.role == "test"


# def test_callback_service():
#     auth = t.OpenIDConnectAuth("test")

#     thread = t.OpenIDConnectCallbackService(56789, auth)
#     thread.start()
#     assert isinstance(thread, threading.Thread)

#     # invalid calls - the thread should not stop
#     resp = httpx.get("http://localhost:56789/invalid-path")
#     assert resp.status_code == HTTPStatus.NOT_FOUND

#     resp = httpx.get("http://localhost:56789/oidc/callback?param=invalid")
#     assert resp.status_code == HTTPStatus.BAD_REQUEST

#     assert thread.is_alive()

#     # valid call - the thread should stop
#     resp = httpx.get("http://localhost:56789/oidc/callback?code=test")
#     assert resp.status_code == HTTPStatus.OK
#     assert resp.headers["Content-Type"].startswith("text/html")
#     assert (
#         "<p>OIDC authentication successful, you can close the browser now.</p>"
#     ) in resp.text

#     thread.join()
#     assert auth.authorization_code == "test"


# def test_stop_callback_service():
#     thread = t.OpenIDConnectCallbackService(56789, None)
#     thread.start()
#     assert thread.is_alive() is True

#     thread.shutdown_server()

#     time.sleep(0.2)
#     assert thread.is_alive() is False

#     thread.shutdown_server()  # should be no error


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
            t.get_authorization_url(
                unittest_client,
                "http://localhost/callback",
                None,
                "test-nonce",
            )
            == "https://auth.example.com/"
        )

    def test_fail(
        self, unittest_respx: respx.MockRouter, unittest_client: httpx.Client
    ):
        unittest_respx.post("/v1/auth/oidc/oidc/auth_url") % 403

        with pytest.raises(AuthenticationError):
            t.get_authorization_url(
                unittest_client,
                "http://localhost/callback",
                "test_role",
                "test-nonce",
            )


def test_request_token_success(
    unittest_respx: respx.MockRouter, unittest_client: httpx.Client
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
        t.request_token(
            unittest_client,
            "http://auth.example.com/?state=sample-state&nonce=sample-nonce",
            "test-code",
            "test-nonce",
        )
        == "sample-token"
    )


def test_request_token_error(
    unittest_respx: respx.MockRouter, unittest_client: httpx.Client
):
    unittest_respx.get("/v1/auth/oidc/oidc/callback") % 403
    assert (
        t.request_token(
            unittest_client,
            "http://auth.example.com/?state=sample-state&nonce=sample-nonce",
            "test-code",
            "test-nonce",
        )
        is None
    )

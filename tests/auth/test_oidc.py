import threading
import time
from http import HTTPStatus
from unittest.mock import Mock

import httpx
import pytest
import respx

import secrets_env.auth.oidc as t
from secrets_env.exception import AuthenticationError


def test_auth__init__():
    # success
    t.OpenIDConnectAuth("default")
    t.OpenIDConnectAuth(None)

    # fail
    with pytest.raises(TypeError):
        t.OpenIDConnectAuth(1234)


def test_auth_method():
    assert isinstance(t.OpenIDConnectAuth.method(), str)


class TestOpenIDConnectAuthLogin:
    def setup_method(self):
        self.auth = t.OpenIDConnectAuth()
        self.client = Mock(spec=httpx.Client)

    def test_login_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            t,
            "get_authorization_url",
            lambda _1, _2, _3, _4: "https://auth.example.com",
        )
        monkeypatch.setattr(
            t, "OpenIDConnectCallbackService", Mock(spec=t.OpenIDConnectCallbackService)
        )

        def mock_open(url):
            assert url == "https://auth.example.com"
            object.__setattr__(self.auth, "authorization_code", "auth-code")

        def mock_get_token(_1, url, code, _4):
            assert url == "https://auth.example.com"
            assert code == "auth-code"
            return "sample-token"

        monkeypatch.setattr("webbrowser.open", mock_open)
        monkeypatch.setattr(t, "request_token", mock_get_token)

        assert self.auth.login(self.client) == "sample-token"

    def test_login_error_1(self, monkeypatch: pytest.MonkeyPatch):
        # Failed to get auth URL
        monkeypatch.setattr(t, "get_authorization_url", lambda *_: None)
        with pytest.raises(AuthenticationError):
            self.auth.login(self.client)

    def test_login_error_2(self, monkeypatch: pytest.MonkeyPatch):
        # Failed to get auth code
        monkeypatch.setattr(
            t, "get_authorization_url", lambda *_: "https://auth.example.com"
        )
        monkeypatch.setattr(
            t, "OpenIDConnectCallbackService", Mock(spec=t.OpenIDConnectCallbackService)
        )
        monkeypatch.setattr("webbrowser.open", lambda _: None)

        with pytest.raises(AuthenticationError):
            self.auth.login(self.client)

    def test_login_error_3(self, monkeypatch: pytest.MonkeyPatch):
        # Failed to get client token
        monkeypatch.setattr(
            t, "get_authorization_url", lambda *_: "https://auth.example.com"
        )
        monkeypatch.setattr(
            t, "OpenIDConnectCallbackService", Mock(spec=t.OpenIDConnectCallbackService)
        )

        def mock_open(url):
            object.__setattr__(self.auth, "authorization_code", "auth-code")

        monkeypatch.setattr("webbrowser.open", mock_open)
        monkeypatch.setattr(t, "request_token", lambda *_: None)

        with pytest.raises(AuthenticationError):
            self.auth.login(self.client)


def test_callback_service():
    auth = t.OpenIDConnectAuth("test")

    thread = t.OpenIDConnectCallbackService(56789, auth)
    thread.start()
    assert isinstance(thread, threading.Thread)

    # invalid calls - the thread should not stop
    resp = httpx.get("http://localhost:56789/invalid-path")
    assert resp.status_code == HTTPStatus.NOT_FOUND

    resp = httpx.get("http://localhost:56789/oidc/callback?param=invalid")
    assert resp.status_code == HTTPStatus.BAD_REQUEST

    assert thread.is_alive()

    # valid call - the thread should stop
    resp = httpx.get("http://localhost:56789/oidc/callback?code=test")
    assert resp.status_code == HTTPStatus.OK
    assert resp.headers["Content-Type"].startswith("text/html")
    assert (
        "<p>OIDC authentication successful, you can close the browser now.</p>"
    ) in resp.text

    thread.join()
    assert auth.authorization_code == "test"


def test_stop_callback_service():
    thread = t.OpenIDConnectCallbackService(56789, None)
    thread.start()
    assert thread.is_alive() is True

    thread.shutdown_server()

    time.sleep(0.2)
    assert thread.is_alive() is False

    thread.shutdown_server()  # should be no error


def test_get_free_port():
    port = t.get_free_port()
    assert isinstance(port, int)
    assert 49152 <= port <= 65535


def test_get_authorization_url_success(
    unittest_respx: respx.MockRouter, unittest_client: httpx.Client
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


def test_get_authorization_url_error(
    unittest_respx: respx.MockRouter, unittest_client: httpx.Client
):
    unittest_respx.post("/v1/auth/oidc/oidc/auth_url") % 403
    assert (
        t.get_authorization_url(
            unittest_client,
            "http://localhost/callback",
            "test_role",
            "test-nonce",
        )
        is None
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

import os
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
import respx
from pydantic_core import ValidationError

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.base import Auth, NoAuth
from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig
from secrets_env.providers.vault.provider import (
    MountMetadata,
    VaultPath,
    create_http_client,
    get_mount,
    get_token,
    is_authenticated,
)


class TestVaultPath:
    def test_success(self):
        path = VaultPath.model_validate("foo#bar")
        assert path == VaultPath(path="foo", field="bar")

    def test_empty(self):
        with pytest.raises(ValidationError):
            VaultPath.model_validate("a#")
        with pytest.raises(ValidationError):
            VaultPath.model_validate("#b")

    def test_invalid(self):
        with pytest.raises(ValidationError):
            VaultPath.model_validate("foobar")
        with pytest.raises(ValidationError):
            VaultPath.model_validate("foo#bar#baz")


class TestCreateHttpClient:
    def test_basic(self):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
        )

        client = create_http_client(config)

        assert isinstance(client, httpx.Client)
        assert client.base_url == httpx.URL("https://vault.example.com/")

    def test_proxy(self):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            proxy="http://proxy.example.com",
        )

        client = create_http_client(config)
        assert isinstance(client, httpx.Client)

    @pytest.fixture()
    def mock_httpx_client(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        monkeypatch.setattr("httpx.Client", client)
        yield client

    def test_ca(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=Path("/mock/ca.pem"),
                client_cert=None,
                client_key=None,
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["verify"] == Path("/mock/ca.pem")

    def test_client_cert(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=None,
                client_cert=Path("/mock/client.pem"),
                client_key=None,
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["cert"] == Path("/mock/client.pem")

    def test_client_cert_pair(self, mock_httpx_client: Mock):
        config = VaultUserConfig(
            url="https://vault.example.com",
            auth="null",
            tls=Mock(
                TlsConfig,
                ca_cert=None,
                client_cert=Path("/mock/client.pem"),
                client_key=Path("/mock/client.key"),
            ),
        )

        create_http_client(config)

        _, kwargs = mock_httpx_client.call_args
        assert kwargs["cert"] == (Path("/mock/client.pem"), Path("/mock/client.key"))


class TestGetToken:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        auth = NoAuth(token="t0ken")
        monkeypatch.setattr(
            "secrets_env.providers.vault.provider.is_authenticated", lambda c, t: True
        )
        assert get_token(client, auth) == "t0ken"

    def test_no_token(self):
        client = Mock(httpx.Client)
        auth = Mock(Auth)
        auth.login.return_value = None

        with pytest.raises(AuthenticationError, match="Absence of token information"):
            get_token(client, auth)

    def test_authenticate_fail(self, monkeypatch: pytest.MonkeyPatch):
        client = Mock(httpx.Client)
        auth = NoAuth(token="t0ken")
        monkeypatch.setattr(
            "secrets_env.providers.vault.provider.is_authenticated", lambda c, t: False
        )
        with pytest.raises(AuthenticationError, match="Invalid token"):
            get_token(client, auth)

    def test_login_connection_error(self):
        client = Mock(httpx.Client)
        auth = Mock(Auth)
        auth.login.side_effect = httpx.ProxyError("test")
        with pytest.raises(
            AuthenticationError, match="Encounter proxy error while retrieving token"
        ):
            get_token(client, auth)

    def test_login_exception(self):
        client = Mock(httpx.Client)
        auth = Mock(Auth)
        auth.login.side_effect = httpx.HTTPError("test")
        with pytest.raises(httpx.HTTPError):
            get_token(client, auth)


class TestIsAuthenticated:

    def test_success(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self")

        client = httpx.Client(base_url="https://vault.example.com")
        assert is_authenticated(client, "test-token") is True

    def test_fail(self, respx_mock: respx.MockRouter):
        respx_mock.get("https://vault.example.com/v1/auth/token/lookup-self").respond(
            status_code=403,
            json={"errors": ["mock permission denied"]},
        )

        client = httpx.Client(base_url="https://vault.example.com")
        assert is_authenticated(client, "test-token") is False

    def test_integration(self):
        url = os.getenv("VAULT_ADDR")
        token = os.getenv("VAULT_TOKEN")
        if not url or not token:
            pytest.skip("VAULT_ADDR or VAULT_TOKEN are not set")

        client = httpx.Client(base_url=url)

        assert is_authenticated(client, token) is True
        assert is_authenticated(client, "invalid-token") is False


class TestGetMount:
    @pytest.fixture()
    def route(self, respx_mock: respx.MockRouter):
        return respx_mock.get(
            "https://example.com/v1/sys/internal/ui/mounts/secrets/test"
        )

    def test_success_kv2(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "options": {"version": "2"},
                        "path": "secrets/",
                        "type": "kv",
                    },
                },
            )
        )
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=2
        )

    def test_success_kv1(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "options": {"version": "1"},
                        "path": "secrets/",
                        "type": "kv",
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="secrets/", version=1
        )

    def test_success_legacy(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(httpx.Response(404))
        assert get_mount(unittest_client, "secrets/test") == MountMetadata(
            path="", version=1
        )

    def test_not_ported_version(
        self, route: respx.Route, unittest_client: httpx.Client
    ):
        route.mock(
            httpx.Response(
                200,
                json={
                    "data": {
                        "path": "mock/",
                        "type": "kv",
                        "options": {"version": "99"},
                    }
                },
            )
        )

        with pytest.raises(ValidationError):
            get_mount(unittest_client, "secrets/test")

    def test_bad_request(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(httpx.Response(400))
        assert get_mount(unittest_client, "secrets/test") is None
        assert "Error occurred during checking metadata for secrets/test" in caplog.text

    def test_connection_error(
        self,
        route: respx.Route,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        route.mock(side_effect=httpx.ConnectError)
        assert get_mount(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during checking metadata for secrets/test: connection error"
            in caplog.text
        )

    def test_http_exception(self, route: respx.Route, unittest_client: httpx.Client):
        route.mock(side_effect=httpx.DecodingError)
        with pytest.raises(httpx.DecodingError):
            get_mount(unittest_client, "secrets/test")

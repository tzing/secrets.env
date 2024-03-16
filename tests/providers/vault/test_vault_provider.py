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
    VaultKvProvider,
    VaultPath,
    create_http_client,
    get_mount,
    get_token,
    is_authenticated,
    read_secret,
)


@pytest.fixture()
def intl_provider() -> VaultKvProvider:
    if "VAULT_ADDR" not in os.environ:
        raise pytest.skip("VAULT_ADDR is not set")
    if "VAULT_TOKEN" not in os.environ:
        raise pytest.skip("VAULT_TOKEN is not set")
    return VaultKvProvider(auth="token")


@pytest.fixture()
def intl_client(intl_provider: VaultKvProvider) -> httpx.Client:
    return intl_provider.client


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
    @pytest.mark.skipif("VAULT_ADDR" in os.environ, reason="VAULT_ADDR is set")
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
        return client

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
        if "VAULT_ADDR" not in os.environ:
            raise pytest.skip("VAULT_ADDR is not set")
        if "VAULT_TOKEN" not in os.environ:
            raise pytest.skip("VAULT_TOKEN is not set")

        client = httpx.Client(base_url=os.getenv("VAULT_ADDR"))

        assert is_authenticated(client, os.getenv("VAULT_TOKEN")) is True
        assert is_authenticated(client, "invalid-token") is False


class TestReadSecret:
    @pytest.fixture()
    def _set_mount_kv2(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.provider.get_mount",
            lambda c, p: MountMetadata(path="secrets/", version=2),
        )

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_kv2(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "9ababbb6-3749-cf2c-5a5b-85660e917e8e",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": {
                        "data": {"test": "mock"},
                        "metadata": {
                            "created_time": "2022-09-20T15:57:45.143053836Z",
                            "custom_metadata": None,
                            "deletion_time": "",
                            "destroyed": False,
                            "version": 1,
                        },
                    },
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        assert read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_kv2_integration(self, intl_client: httpx.Client):
        assert read_secret(intl_client, "kv2/test") == {
            "foo": "hello, world",
            "test": {"name.with-dot": "sample-value"},
        }

    def test_kv1(
        self,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.provider.get_mount",
            lambda c, p: MountMetadata(path="secrets/", version=1),
        )
        respx_mock.get("https://example.com/v1/secrets/test").mock(
            httpx.Response(
                200,
                json={
                    "request_id": "a8f28d97-8a9d-c9dd-4d86-e815083b33ad",
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 2764800,
                    "data": {"test": "mock"},
                    "wrap_info": None,
                    "warnings": None,
                    "auth": None,
                },
            )
        )

        assert read_secret(unittest_client, "secrets/test") == {"test": "mock"}

    def test_kv1_integration(self, intl_client: httpx.Client):
        assert read_secret(intl_client, "kv1/test") == {"foo": "hello"}

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_not_found(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(404)
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert "Secret <data>secrets/test</data> not found" in caplog.text

    def test_get_mount_error(
        self, monkeypatch: pytest.MonkeyPatch, unittest_client: httpx.Client
    ):
        monkeypatch.setattr(
            "secrets_env.providers.vault.provider.get_mount", lambda c, p: None
        )
        assert read_secret(unittest_client, "secrets/test") is None

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_connection_error(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.ProxyError
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert (
            "Error occurred during query secret secrets/test: proxy error"
            in caplog.text
        )

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_http_exception(
        self, respx_mock: respx.MockRouter, unittest_client: httpx.Client
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            side_effect=httpx.DecodingError
        )
        with pytest.raises(httpx.DecodingError):
            read_secret(unittest_client, "secrets/test")

    @pytest.mark.usefixtures("_set_mount_kv2")
    def test_bad_request(
        self,
        respx_mock: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        respx_mock.get("https://example.com/v1/secrets/data/test").mock(
            httpx.Response(499)
        )
        assert read_secret(unittest_client, "secrets/test") is None
        assert "Error occurred during query secret secrets/test" in caplog.text


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

    def test_success_kv2_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv2/test") == MountMetadata(
            path="kv2/", version=2
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

    def test_success_kv1_integration(self, intl_client: httpx.Client):
        assert get_mount(intl_client, "kv1/test") == MountMetadata(
            path="kv1/", version=1
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

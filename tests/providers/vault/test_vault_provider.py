import os
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
import respx

from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig
from secrets_env.providers.vault.provider import create_http_client, is_authenticated


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


class TestGetToken: ...  # FIXME


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

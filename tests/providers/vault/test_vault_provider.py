from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig
from secrets_env.providers.vault.provider import create_http_client


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

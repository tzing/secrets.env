from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport.adapters as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.config import AppParameter
from secrets_env.providers.teleport.helper import AppConnectionInfo


def test_handle(monkeypatch: pytest.MonkeyPatch):
    def mock_get_adapter(name):
        assert name == "Test"
        return Mock(return_value={"test": "result"})

    def mock_parse_adapter_config(data):
        assert isinstance(data, dict)
        return Mock(spec=AppParameter)

    def mock_get_connection_info(param):
        assert isinstance(param, dict)
        return Mock(spec=AppConnectionInfo)

    monkeypatch.setattr(t, "get_adapter", mock_get_adapter)
    monkeypatch.setattr(t, "parse_adapter_config", mock_parse_adapter_config)
    monkeypatch.setattr(t, "get_connection_info", mock_get_connection_info)

    assert t.handle("Test", {"test": "input"}) == {"test": "result"}


def test_get_adapter():
    assert callable(t.get_adapter("Vault"))

    with pytest.raises(ConfigError):
        t.get_adapter("no-this-type")


@pytest.fixture()
def conn_info():
    return AppConnectionInfo(
        uri="https://example.com",
        ca=None,
        cert=b"cert",
        key=b"key",
    )


def test_adapt_vault_provider(
    monkeypatch: pytest.MonkeyPatch, conn_info: AppConnectionInfo
):
    def mock_load(type_, data):
        assert data["url"] == "https://example.com"
        assert len(data["tls"]) == 2
        assert isinstance(data["tls"]["client_cert"], Path)
        assert isinstance(data["tls"]["client_key"], Path)
        return Mock(spec=ProviderBase)

    monkeypatch.setattr("secrets_env.providers.vault.get_provider", mock_load)

    provider = t.adapt_vault_provider(
        "vault", {"url": "http://invalid.example.com", "auth": "oidc"}, conn_info
    )
    assert isinstance(provider, ProviderBase)

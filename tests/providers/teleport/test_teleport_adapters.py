from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport.adapters as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.helper import AppConnectionInfo


def test_get_adapter():
    assert callable(t.get_adapter("vault"))

    with pytest.raises(ConfigError):
        t.get_adapter("no-this-type")


@pytest.fixture()
def conn_info():
    return AppConnectionInfo(
        uri="https://example.com",
        ca=None,
        cert=Path(__file__),
        key=Path(__file__),
    )


def test_adapt_vault_provider(
    monkeypatch: pytest.MonkeyPatch, conn_info: AppConnectionInfo
):
    def mock_load(type_, data):
        assert data == {
            "url": "https://example.com",
            "auth": "oidc",
            "tls": {
                "client_cert": Path(__file__),
                "client_key": Path(__file__),
            },
        }
        return Mock(spec=ProviderBase)

    monkeypatch.setattr("secrets_env.providers.vault.get_provider", mock_load)

    provider = t.adapt_vault_provider(
        "vault", {"url": "http://invalid.example.com", "auth": "oidc"}, conn_info
    )
    assert isinstance(provider, ProviderBase)

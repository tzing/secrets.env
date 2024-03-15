from pathlib import Path
from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport.adapters as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import Provider
from secrets_env.providers.teleport.config import TeleportConnectionParameter


def test_get_adapter():
    assert callable(t.get_adapter("Vault"))

    with pytest.raises(ConfigError):
        t.get_adapter("no-this-type")


def test_adapt_vault_provider(monkeypatch: pytest.MonkeyPatch):
    def mock_load(type_, data):
        assert data["url"] == "https://example.com"
        assert len(data["tls"]) == 2
        assert isinstance(data["tls"]["client_cert"], Path)
        assert isinstance(data["tls"]["client_key"], Path)
        return Mock(spec=Provider)

    monkeypatch.setattr("secrets_env.providers.vault.get_provider", mock_load)

    provider = t.adapt_vault_provider(
        type_="vault",
        data={"url": "http://invalid.example.com", "auth": "oidc"},
        param=TeleportConnectionParameter(
            uri="https://example.com",
            ca=None,
            cert=b"cert",
            key=b"key",
        ),
    )
    assert isinstance(provider, Provider)

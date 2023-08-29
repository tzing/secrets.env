from unittest.mock import Mock

import pytest

import secrets_env.providers as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase


def mock_get_provider(type_, data):
    return Mock(spec=ProviderBase)


class TestGetProvider:
    def test_null(self):
        p = t.get_provider({"type": "NULL"})
        assert p.get({}) == ""

    def test_vault(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.vault.get_provider", mock_get_provider
        )
        assert isinstance(t.get_provider({"type": "Vault"}), ProviderBase)

    def test_teleport(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.get_provider", mock_get_provider
        )
        assert isinstance(t.get_provider({"type": "Teleport"}), ProviderBase)

    def test_teleport_adapter(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.teleport.get_adapted_provider", mock_get_provider
        )
        assert isinstance(t.get_provider({"type": "Teleport+Test"}), ProviderBase)

    def test_plain(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.providers.plain.get_provider", mock_get_provider
        )
        assert isinstance(t.get_provider({"type": "plain"}), ProviderBase)

    def test_not_found(self):
        with pytest.raises(ConfigError):
            t.get_provider({"type": "no-this-type"})

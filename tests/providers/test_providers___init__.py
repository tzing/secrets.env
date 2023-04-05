from unittest.mock import Mock

import pytest

import secrets_env.providers as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase

mock_provider = Mock(spec=ProviderBase)


class TestGetProvider:
    def test_vault(self, monkeypatch: pytest.MonkeyPatch):
        def mock_load(type_, data):
            return mock_provider

        monkeypatch.setattr("secrets_env.providers.vault.get_provider", mock_load)
        assert t.get_provider({"type": "Vault"}) is mock_provider

    def test_plugin(self):
        assert t.get_provider({"type": "plugin"}) is mock_provider

    def test_plugin_error(self):
        with pytest.raises(ConfigError):
            t.get_provider({"type": "MALFORM"})

    def test_not_found(self):
        with pytest.raises(ConfigError):
            t.get_provider({"type": "no-this-type"})

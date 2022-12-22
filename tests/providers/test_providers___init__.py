from unittest.mock import Mock

import pytest

import secrets_env.hooks
import secrets_env.providers as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase

mock_provider = Mock(spec=ProviderBase)


class MockPlugin:
    @secrets_env.hooks.hookimpl
    def get_provider(self, type: str, data: dict):
        if type == "plugin":
            return mock_provider
        elif type == "malform":
            raise ConfigError("test malformed config")
        else:
            return None


class TestGetProvider:
    @pytest.fixture(autouse=True, scope="class")
    def _install_plugin(self):
        # get hook manager
        secrets_env.hooks.get_hooks()
        mgr = secrets_env.hooks._manager

        # register
        plugin = MockPlugin()
        mgr.register(plugin)
        yield
        mgr.unregister(plugin)

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

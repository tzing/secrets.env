from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.config import TeleportUserConfig
from secrets_env.providers.teleport.provider import TeleportProvider


def test_get_provider():
    provider = t.get_provider("teleport", {"app": "test"})
    assert isinstance(provider, TeleportProvider)


class TestGetAdaptedProvider:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_factory(subtype, data, param):
            assert subtype == "Test"
            assert isinstance(data, dict)
            assert isinstance(param, TeleportUserConfig)
            return Mock(spec=ProviderBase)

        def mock_get_adapter(subtype):
            assert subtype == "Test"
            return mock_factory

        monkeypatch.setattr(
            "secrets_env.providers.teleport.adapters.get_adapter",
            mock_get_adapter,
        )
        monkeypatch.setattr(
            TeleportUserConfig,
            "get_connection_param",
            lambda _: Mock(spec=TeleportUserConfig),
        )

        config = {
            "teleport": {
                "app": "test",
            }
        }
        provider = t.get_adapted_provider("teleport+Test", config)

        assert isinstance(provider, ProviderBase)

    def test_fail(self):
        with pytest.raises(ConfigError):
            t.get_adapted_provider("not-teleport+other", {})
        with pytest.raises(ConfigError):  # raise by get_adapter
            t.get_adapted_provider("teleport+no-this-type", {})

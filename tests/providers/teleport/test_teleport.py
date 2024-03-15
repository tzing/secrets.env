from unittest.mock import Mock, PropertyMock

import pytest

import secrets_env.providers.teleport as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import Provider
from secrets_env.providers.teleport.config import TeleportUserConfig


class TestGetAdaptedProvider:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_factory(subtype, data, param):
            assert subtype == "Test"
            assert isinstance(data, dict)
            assert isinstance(param, TeleportUserConfig)
            return Mock(Provider)

        def mock_get_adapter(subtype):
            assert subtype == "Test"
            return mock_factory

        monkeypatch.setattr(
            "secrets_env.providers.teleport.adapters.get_adapter",
            mock_get_adapter,
        )
        monkeypatch.setattr(
            TeleportUserConfig,
            "connection_param",
            PropertyMock(return_value=Mock(TeleportUserConfig)),
        )

        config = {
            "teleport": {
                "app": "test",
            }
        }
        provider = t.get_adapted_provider("teleport+Test", config)

        assert isinstance(provider, Provider)

    def test_fail(self):
        with pytest.raises(ConfigError):
            t.get_adapted_provider("not-teleport+other", {})
        with pytest.raises(ConfigError):  # raise by get_adapter
            t.get_adapted_provider("teleport+no-this-type", {})

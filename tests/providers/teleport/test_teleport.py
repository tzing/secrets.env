from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.helper import AppConnectionInfo
from secrets_env.providers.teleport.provider import TeleportProvider


def test_get_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "secrets_env.providers.teleport.config.parse_source_config",
        lambda _: {"app": "test"},
    )
    monkeypatch.setattr(
        "secrets_env.providers.teleport.provider.TeleportProvider",
        lambda **kwargs: Mock(spec=TeleportProvider),
    )
    assert isinstance(t.get_provider("teleport", {}), TeleportProvider)


class TestGetAdaptedProvider:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_factory(subtype, data, conn_info):
            assert subtype == "Test"
            assert isinstance(data, dict)
            assert isinstance(conn_info, AppConnectionInfo)
            return Mock(spec=ProviderBase)

        def mock_get_adapter(subtype):
            assert subtype == "Test"
            return mock_factory

        monkeypatch.setattr(
            "secrets_env.providers.teleport.adapters.get_adapter",
            mock_get_adapter,
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.config.parse_adapter_config", Mock()
        )
        monkeypatch.setattr(
            "secrets_env.providers.teleport.helper.get_connection_info",
            lambda _: Mock(spec=AppConnectionInfo),
        )

        assert isinstance(t.get_adapted_provider("Teleport+Test", {}), ProviderBase)

    def test_fail(self):
        with pytest.raises(ConfigError):
            t.get_adapted_provider("not-teleport+other", {})
        with pytest.raises(ConfigError):  # raise by get_adapter
            t.get_adapted_provider("teleport+no-this-type", {})

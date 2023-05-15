from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase


def test_get_provider_success(monkeypatch: pytest.MonkeyPatch):
    def mock_get_adapter(type_):
        assert type_ == "test"
        return mock_adapter

    def mock_adapter(type_, data, _3):
        assert type_ == "test"
        assert data == {"test": "foo"}
        return Mock(spec=ProviderBase)

    monkeypatch.setattr(
        "secrets_env.providers.teleport.adapters.get_adapter", mock_get_adapter
    )
    monkeypatch.setattr(
        "secrets_env.providers.teleport.config.parse_config", lambda _: Mock()
    )
    monkeypatch.setattr(
        "secrets_env.providers.teleport.helper.get_connection_info", lambda _: Mock()
    )

    provider = t.get_provider("teleport+test", {"test": "foo"})
    assert isinstance(provider, ProviderBase)


def test_get_provider_fail():
    with pytest.raises(ConfigError):
        t.get_provider("test", {"test": "foo"})

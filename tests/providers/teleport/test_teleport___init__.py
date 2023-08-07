from unittest.mock import Mock

import pytest

import secrets_env.providers.teleport as t
from secrets_env.exceptions import ConfigError
from secrets_env.provider import ProviderBase


class TestGetProvider:
    def test_adapter(self, monkeypatch: pytest.MonkeyPatch):
        def mock_handle(name, data):
            assert name == "Test"
            assert isinstance(data, dict)
            return Mock(spec=ProviderBase)

        monkeypatch.setattr(
            "secrets_env.providers.teleport.adapters.handle", mock_handle
        )

        provider = t.get_provider("Teleport+Test", {"test": "foo"})
        assert isinstance(provider, ProviderBase)

    def test_failed(self):
        with pytest.raises(ConfigError):
            t.get_provider("test", {"test": "foo"})

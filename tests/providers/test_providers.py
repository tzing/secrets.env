import pytest

from secrets_env.providers import get_provider
from secrets_env.providers.null import NullProvider
from secrets_env.providers.plain import PlainTextProvider
from secrets_env.providers.teleport import TeleportProvider
from secrets_env.providers.vault import VaultKvProvider


class TestGetProvider:
    def test_null(self):
        provider = get_provider({"type": "null"})
        assert isinstance(provider, NullProvider)

    def test_plain(self):
        provider = get_provider({"type": "plain"})
        assert isinstance(provider, PlainTextProvider)

    def test_teleport(self):
        provider = get_provider({"type": "teleport", "app": "test"})
        assert isinstance(provider, TeleportProvider)

    def test_teleport_adapter(self):
        with pytest.raises(NotImplementedError):
            get_provider({"type": "teleport+vault"})

    def test_vault(self):
        provider = get_provider({"url": "https://example.com/", "auth": "null"})
        assert isinstance(provider, VaultKvProvider)

    def test_invalid(self):
        with pytest.raises(ValueError, match="Unknown provider type 'invalid'"):
            get_provider({"type": "invalid"})


class TestNullProvider:
    def test_get(self):
        provider = NullProvider()
        assert provider.get("test") == ""
        assert provider.get({"value": "test"}) == ""


class TestPlainTextProvider:
    def test(self):
        provider = PlainTextProvider()
        assert provider.get("test") == "test"
        assert provider.get("") == ""

        assert provider.get({"value": "test"}) == "test"
        assert provider.get({"value": None}) == ""
        assert provider.get({"value": ""}) == ""

        assert provider.get({"invalid": "foo"}) == ""

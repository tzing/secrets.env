import pytest

from secrets_env.exceptions import NoValue
from secrets_env.provider import Request
from secrets_env.providers import get_provider
from secrets_env.providers.debug import DebugProvider
from secrets_env.providers.plain import PlainTextProvider
from secrets_env.providers.teleport import TeleportProvider, TeleportUserConfig
from secrets_env.providers.vault import VaultKvProvider


class TestGetProvider:
    def test_debug(self):
        provider = get_provider({"type": "debug", "value": "test"})
        assert isinstance(provider, DebugProvider)

    def test_plain(self):
        provider = get_provider({"type": "plain"})
        assert isinstance(provider, PlainTextProvider)

    def test_teleport(self):
        provider = get_provider({"type": "teleport", "app": "test"})
        assert isinstance(provider, TeleportProvider)

    @pytest.mark.filterwarnings("ignore::DeprecationWarning:secrets_env.providers")
    def test_teleport_adapter(self):
        provider = get_provider(
            {"type": "teleport+vault", "auth": "null", "teleport": {"app": "test"}}
        )
        assert isinstance(provider, VaultKvProvider)
        assert isinstance(provider.teleport, TeleportUserConfig)

    @pytest.mark.filterwarnings("ignore::UserWarning:secrets_env.providers")
    def test_vault(self):
        provider = get_provider({"url": "https://example.com/", "auth": "null"})
        assert isinstance(provider, VaultKvProvider)

    def test_invalid(self):
        with pytest.raises(ValueError, match="Unknown provider type 'invalid'"):
            get_provider({"type": "invalid"})


class TestDebugProvider:
    def test(self):
        provider = DebugProvider(value="bar")
        assert provider.name == "debug"
        assert provider(Request(name="test", value="foo")) == "bar"


class TestPlainTextProvider:
    def test(self):
        provider = PlainTextProvider()
        assert provider.name == "plain"
        assert provider(Request(name="test", value="foo")) == "foo"
        assert provider(Request(name="test", value="")) == ""

        with pytest.raises(NoValue):
            provider(Request(name="test"))

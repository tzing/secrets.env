from secrets_env.providers.null import NullProvider
from secrets_env.providers.plain import PlainTextProvider


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

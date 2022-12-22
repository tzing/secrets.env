import pytest

import secrets_env.providers.vault as t
from secrets_env.exceptions import ConfigError
from secrets_env.providers.vault.provider import KvProvider


class TestGetProvider:
    def test_success(self):
        out = t.get_provider("vault", {"url": "https://example.com", "auth": "null"})
        assert isinstance(out, KvProvider)

    def test_fail(self):
        with pytest.raises(ConfigError):
            t.get_provider("vault", {})

    def test_not_related(self):
        with pytest.raises(ConfigError):
            t.get_provider("something-else", {})

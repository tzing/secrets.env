import httpx
import pytest

from secrets_env.realms.server import ThreadSafeDict


class TestThreadSafeDict:
    def test(self):
        d = ThreadSafeDict()
        d["foo"] = "bar"
        d.setdefault("bar", "baz")
        assert len(d) == 2
        assert repr(d) == "{'foo': 'bar', 'bar': 'baz'}"

        assert d.pop("bar") == "baz"
        assert "bar" not in d
        assert list(d) == ["foo"]

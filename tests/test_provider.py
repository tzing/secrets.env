import pytest
from pydantic_core import ValidationError

from secrets_env.provider import Provider, Request


class TestRequest:
    def test_success(self):
        cfg = Request.model_validate({"name": "foo", "value": "bar"})
        assert cfg == Request(name="foo", value="bar")

    def test_fail(self):
        with pytest.raises(ValidationError, match="Invalid environment variable name"):
            Request.model_validate({"name": "0foo"})


class TestProvider:

    def test_get(self):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request) -> str:
                return "bar"

        provider = DummyProvider()
        assert provider(Request(name="foo")) == "bar"

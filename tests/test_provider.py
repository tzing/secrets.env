import pytest
from pydantic import BaseModel, ValidationError

from secrets_env.exceptions import AuthenticationError, NoValue, UnsupportedError
from secrets_env.provider import AsyncProvider, Provider, Request


class TestRequest:
    def test_success(self):
        cfg = Request.model_validate({"name": "foo", "value": "bar"})
        assert cfg == Request(name="foo", value="bar")

    def test_fail(self):
        with pytest.raises(ValidationError, match="String should match pattern"):
            Request.model_validate({"name": "0foo"})


class TestProvider:

    def test_success(self):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request) -> str:
                return "bar"

        provider = DummyProvider()
        assert provider(Request(name="foo")) == "bar"

    def test_auth_error(self, caplog: pytest.LogCaptureFixture):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request):
                raise AuthenticationError("test error")

        provider = DummyProvider()
        with pytest.raises(NoValue):
            provider(Request(name="foo"))

        assert "Authentication failed for <data>foo</data>: test error" in caplog.text

    def test_lookup_error(self, caplog: pytest.LogCaptureFixture):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request):
                raise LookupError("test error")

        provider = DummyProvider()
        with pytest.raises(NoValue):
            provider(Request(name="foo"))

        assert "Value for <data>foo</data> not found" in caplog.text

    def test_unsupported_error(self, caplog: pytest.LogCaptureFixture):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request):
                raise UnsupportedError("test error")

        provider = DummyProvider()
        with pytest.raises(NoValue):
            provider(Request(name="foo"))

        assert "Operation not supported for <data>foo</data>: test error" in caplog.text

    def test_validation_error(self, caplog: pytest.LogCaptureFixture):
        class DummyRequest(BaseModel):
            path: str
            foobar: str

        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request):
                DummyRequest.model_validate(spec.model_dump())

        provider = DummyProvider()
        with pytest.raises(NoValue):
            provider(Request(name="foo"))

        assert "Request <data>foo</data> is malformed:" in caplog.text
        assert "➜ <mark>path</mark>: Input should be a valid string" in caplog.text
        assert "➜ <mark>foobar</mark>: Field required" in caplog.text

    def test_exception(self, caplog: pytest.LogCaptureFixture):
        class DummyProvider(Provider):
            type = "dummy"

            def _get_value_(self, spec: Request):
                raise RuntimeError("test error")

        provider = DummyProvider()
        with (
            pytest.raises(NoValue),
            caplog.at_level("DEBUG"),
        ):
            provider(Request(name="foo"))

        assert "Error requesting value for <data>foo</data>" in caplog.text
        assert "Request= Request(name='foo', " in caplog.text
        assert "Error= RuntimeError, Msg= test error" in caplog.text


class DummyAsyncProviderBase(AsyncProvider):

    type = "dummy"


class TestAsyncProvider:

    @pytest.mark.asyncio
    async def test_success(self):
        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request) -> str:
                return "bar"

        provider = MyProvider.model_validate({})
        assert await provider(Request(name="foo")) == "bar"

    @pytest.mark.asyncio
    async def test_auth_error(self, caplog: pytest.LogCaptureFixture):
        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request):
                raise AuthenticationError("test error")

        provider = MyProvider.model_validate({})
        with pytest.raises(NoValue):
            await provider(Request(name="foo"))

        assert "Authentication failed for <data>foo</data>: test error" in caplog.text

    @pytest.mark.asyncio
    async def test_lookup_error(self, caplog: pytest.LogCaptureFixture):
        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request):
                raise LookupError("test error")

        provider = MyProvider.model_validate({})
        with pytest.raises(NoValue):
            await provider(Request(name="foo"))

        assert "Value for <data>foo</data> not found" in caplog.text

    @pytest.mark.asyncio
    async def test_unsupported_error(self, caplog: pytest.LogCaptureFixture):
        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request):
                raise UnsupportedError("test error")

        provider = MyProvider.model_validate({})
        with pytest.raises(NoValue):
            await provider(Request(name="foo"))

        assert "Operation not supported for <data>foo</data>: test error" in caplog.text

    @pytest.mark.asyncio
    async def test_validation_error(self, caplog: pytest.LogCaptureFixture):
        class DummyRequest(BaseModel):
            path: str
            foobar: str

        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request):
                DummyRequest.model_validate(spec.model_dump())

        provider = MyProvider.model_validate({})
        with pytest.raises(NoValue):
            await provider(Request(name="foo"))

        assert "Request <data>foo</data> is malformed:" in caplog.text
        assert "➜ <mark>path</mark>: Input should be a valid string" in caplog.text
        assert "➜ <mark>foobar</mark>: Field required" in caplog.text

    @pytest.mark.asyncio
    async def test_exception(self, caplog: pytest.LogCaptureFixture):
        class MyProvider(DummyAsyncProviderBase):
            async def _get_value_(self, spec: Request):
                raise RuntimeError("test error")

        provider = MyProvider.model_validate({})
        with (
            pytest.raises(NoValue),
            caplog.at_level("DEBUG"),
        ):
            await provider(Request(name="foo"))

        assert "Error requesting value for <data>foo</data>" in caplog.text
        assert "Request= Request(name='foo', " in caplog.text
        assert "Error= RuntimeError, Msg= test error" in caplog.text

import pytest
from pydantic import ValidationError

from secrets_env.config.parser import (
    LocalConfig,
    ProviderBuilder,
    Request,
    RequestBuilder,
)
from secrets_env.providers.plain import PlainTextProvider


class TestProviderBuilder:

    def test_success__dict(self):
        model = ProviderBuilder.model_validate(
            {
                "source": {"name": "item1", "type": "plain"},
                "sources": {"name": "item2", "type": "plain"},
            }
        )
        assert model == ProviderBuilder(
            source=[PlainTextProvider(name="item1")],
            sources=[PlainTextProvider(name="item2")],
        )

    def test_success__empty(self):
        model = ProviderBuilder.model_validate({})
        assert model == ProviderBuilder()
        assert model.source == []
        assert model.sources == []

    def test_value_error(self):
        with pytest.raises(ValidationError, match="sources") as exc_info:
            ProviderBuilder(
                source=[
                    {"name": "item1", "type": "plain"},
                    {"name": "item2", "type": "invalid"},
                ],
                sources=[
                    {"name": "item3", "type": "debug"},
                    {"name": "item4", "type": "plain"},
                ],
            )

        exc_info.match("source.1.type")
        exc_info.match("sources.0.value")
        exc_info.match("Unknown provider type 'invalid'")

    def test_type_error(self):
        with pytest.raises(ValidationError, match="sources"):
            ProviderBuilder(sources=1234)

    def test_iter(self):
        model = ProviderBuilder(
            source=[{"name": "item1", "type": "plain"}],
            sources=[{"name": "item2", "type": "plain"}],
        )
        assert list(model.iter()) == [
            PlainTextProvider(name="item1"),
            PlainTextProvider(name="item2"),
        ]

    def test_collect(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "plain"},
                {"name": "item2", "type": "plain"},
            ],
        )
        assert model.collect() == {
            "item1": PlainTextProvider(name="item1"),
            "item2": PlainTextProvider(name="item2"),
        }

    def test_collect_error_1(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "plain"},
                {"name": "item1", "type": "plain"},
                {"type": "plain"},
            ],
        )

        with pytest.raises(ValidationError, match="duplicate source name"):
            model.collect()

    def test_collect_error_2(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "plain"},
                {"type": "plain"},
            ],
        )

        with pytest.raises(
            ValidationError,
            match="source must have names when using multiple sources",
        ):
            model.collect()


class TestRequest:
    def test_success(self):
        cfg = Request.model_validate({"name": "foo", "value": "bar"})
        assert cfg == Request(name="foo", value="bar")

    def test_fail(self):
        with pytest.raises(ValidationError, match="Invalid environment variable name"):
            Request.model_validate({"name": "0foo"})


class TestRequestBuilder:
    def test_success__model(self):
        model = RequestBuilder.model_validate(
            {
                "secret": {
                    "item1": Request(name="item1"),
                }
            }
        )
        assert model.secret == [Request(name="item1")]
        assert model.secrets == []

    def test_success__list(self):
        model = RequestBuilder.model_validate(
            {
                "secret": [{"name": "item1", "path": "/path/item1"}],
            }
        )
        assert list(model.iter()) == [
            Request(name="item1", path="/path/item1"),
        ]

    def test_success__dict(self):
        model = RequestBuilder.model_validate(
            {
                "secret": {
                    "item1": {"path": "/path/item1"},
                    "item2": "value2",
                },
            }
        )
        assert list(model.iter()) == [
            Request(name="item1", path="/path/item1"),
            Request(name="item2", value="value2"),
        ]

    def test_error__list(self):
        with pytest.raises(ValidationError, match="secret.0.name"):
            RequestBuilder.model_validate(
                {
                    "secret": [{"name": "1nvalid"}],
                }
            )

    def test_error__dict(self):
        with pytest.raises(ValidationError, match="secret.1nvalid.name"):
            RequestBuilder.model_validate(
                {
                    "secret": {
                        "1nvalid": {},
                    },
                }
            )

    def test_error_type(self):
        with pytest.raises(
            ValidationError, match="Input must be a list or a dictionary"
        ):
            RequestBuilder.model_validate({"secret": 1234})


class TestLocalConfig:
    def test_success(self):
        cfg = LocalConfig.model_validate(
            {
                "source": {"name": "source-1", "type": "plain"},
                "secret": {"key1": {"source": "source-1", "path": "/mock/path"}},
            }
        )

        assert cfg.providers["source-1"] == PlainTextProvider(name="source-1")
        assert cfg.requests[0] == Request(
            name="key1", source="source-1", path="/mock/path"
        )

    def test_error(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": {"type": "debug"},
                    "secret": [{"name": "invalid.x"}],
                }
            )

        exc_info.match("sources.0.value")
        exc_info.match("secret.0.name")

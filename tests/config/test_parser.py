import pytest
from pydantic import ValidationError

from secrets_env.config.parser import ProviderBuilder
from secrets_env.providers.null import NullProvider


class TestProviderBuilder:

    def test_init_dict(self):
        model = ProviderBuilder.model_validate(
            {
                "source": {"name": "item1"},
                "sources": {"name": "item2"},
            }
        )
        assert model == ProviderBuilder(
            source=[{"name": "item1"}], sources=[{"name": "item2"}]
        )

    def test_init_empty(self):
        model = ProviderBuilder.model_validate({})
        assert model == ProviderBuilder()
        assert model.source == []
        assert model.sources == []

    def test_iter(self):
        model = ProviderBuilder(
            source=[{"name": "item1", "type": "null"}],
            sources=[{"name": "item2", "type": "null"}],
        )
        assert list(model) == [
            NullProvider(name="item1"),
            NullProvider(name="item2"),
        ]

    def test_iter_error(self):
        model = ProviderBuilder(
            source=[
                {"name": "item1", "type": "null"},
                {"name": "item2", "type": "invalid"},
            ],
            sources=[
                {"name": "item3", "type": "vault"},
                {"name": "item4", "type": "null"},
            ],
        )

        with pytest.raises(ValidationError, match="sources") as exc_info:
            list(model)

        exc_info.match("source.1.type")
        exc_info.match("sources.0.url")
        exc_info.match("Unknown provider type 'invalid'")

    def test_collect(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "null"},
                {"name": "item2", "type": "null"},
            ],
        )
        assert model.collect() == {
            "item1": NullProvider(name="item1"),
            "item2": NullProvider(name="item2"),
        }

    def test_collect_error_1(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "null"},
                {"name": "item1", "type": "null"},
                {"type": "null"},
            ],
        )

        with pytest.raises(ValidationError, match="duplicate source name"):
            model.collect()

    def test_collect_error_2(self):
        model = ProviderBuilder(
            sources=[
                {"name": "item1", "type": "null"},
                {"type": "null"},
            ],
        )

        with pytest.raises(
            ValidationError,
            match="source must have unique names when using multiple sources",
        ):
            model.collect()

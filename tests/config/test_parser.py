import pytest
from pydantic import BaseModel, FilePath, ValidationError

from secrets_env.config.parser import (
    LocalConfig,
    ProviderAdapter,
    RequestAdapter,
    capture_line_errors,
)
from secrets_env.provider import Request
from secrets_env.providers.plain import PlainTextProvider


class TestProviderAdapter:
    def test_success(self):
        model = ProviderAdapter.model_validate(
            {
                "source": {"name": "item1", "type": "plain"},
                "sources": [PlainTextProvider(name="item2")],
            }
        )
        assert model == ProviderAdapter(
            providers={
                "item1": PlainTextProvider(name="item1"),
                "item2": PlainTextProvider(name="item2"),
            }
        )

    def test_empty(self):
        model = ProviderAdapter.model_validate({})
        assert model == ProviderAdapter()
        assert model.providers == {}

    def test_value_error(self):
        with pytest.raises(ValidationError, match="sources") as exc_info:
            ProviderAdapter(
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
            ProviderAdapter(sources=1234)

    def test_dupe_name(self):
        with pytest.raises(ValidationError, match="duplicated source name"):
            ProviderAdapter(
                sources=[
                    {"name": "item1", "type": "plain"},
                    {"name": "item1", "type": "plain"},
                    {"type": "plain"},
                ],
            )

    def test_missing_name(self):
        with pytest.raises(
            ValidationError,
            match="naming each source is mandatory when using multiple sources",
        ):
            ProviderAdapter(
                sources=[
                    {"name": "item1", "type": "plain"},
                    {"type": "plain"},
                ],
            )


class TestRequestAdapter:
    def test_success(self):
        model = RequestAdapter.model_validate(
            {
                "secrets": [
                    {"name": "item1", "path": "/path/item1"},
                ],
                "secret": {
                    "item2": Request(name="item2"),
                    "item3": "/path/item3",
                },
            }
        )
        assert model.requests == [
            Request(name="item2"),
            Request(name="item3", value="/path/item3"),
            Request(name="item1", path="/path/item1"),
        ]

    def test_error_duplicated_name(self):
        with pytest.raises(ValidationError, match="secrets.item1"):
            RequestAdapter.model_validate(
                {
                    "secret": [
                        Request(name="item1"),
                        Request(name="item1"),
                    ]
                }
            )

    def test_error_from_list(self):
        with pytest.raises(ValidationError, match="secret.0.name"):
            RequestAdapter.model_validate(
                {
                    "secret": [{"name": "1nvalid"}],
                }
            )

    def test_error_from_dict(self):
        with pytest.raises(ValidationError, match="secret.1nvalid.name"):
            RequestAdapter.model_validate(
                {
                    "secret": {
                        "1nvalid": {},
                    },
                }
            )

    def test_type_error(self):
        with pytest.raises(ValidationError, match="Expected list or dict"):
            RequestAdapter.model_validate({"secret": 1234})


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

    def test_nested_error(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": {"type": "debug"},
                    "secret": [{"name": "invalid.x"}],
                }
            )

        exc_info.match("sources.0.value")
        exc_info.match("secret.0.name")

    def test_reference_error_1(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": {"type": "plain"},
                    "secret": [
                        {"name": "DEMO", "source": "invalid"},
                    ],
                }
            )

        exc_info.match("secrets.DEMO.source")
        exc_info.match('source "invalid" not found')

    def test_reference_error_2(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": {"type": "plain", "name": "blah"},
                    "secret": [
                        {"name": "FOOBAR"},
                    ],
                }
            )

        exc_info.match("secrets.FOOBAR.source")
        exc_info.match("Field required")


class TestCaptureLineErrors:

    def test_pass(self):
        class Demo(BaseModel): ...

        errors = []
        with capture_line_errors(errors, ("test")):
            Demo()

        assert errors == []

    def test_capture_1(self):
        class Demo(BaseModel):
            name: str
            file: FilePath

        errors = []
        with capture_line_errors(errors, ("test",)):
            Demo(name=1234, file="/not/a/file")

        assert errors[0]["input"] == 1234
        assert errors[0]["loc"] == ("test", "name")
        assert errors[0]["type"] == "string_type"
        assert errors[1]["input"] == "/not/a/file"
        assert errors[1]["loc"] == ("test", "file")
        assert errors[1]["type"] == "value_error"

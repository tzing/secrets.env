import pytest
from dirty_equals import IsInstance
from pydantic import BaseModel, FilePath, ValidationError

from secrets_env.config.parser import (
    LocalConfig,
    ProviderBuilder,
    RequestBuilder,
    capture_line_errors,
)
from secrets_env.provider import Request
from secrets_env.providers.debug import AsyncDebugProvider, DebugProvider


class TestLocalConfig:

    def test_success(self):
        model = LocalConfig.model_validate(
            {
                "sources": {"type": "debug", "value": "foobar"},
                "secrets": [
                    {"name": "secret1"},
                    {"name": "secret2", "source": "debug"},
                ],
            }
        )

        assert model.sources == [IsInstance(DebugProvider)]
        assert model.secrets == [IsInstance(Request), IsInstance(Request)]

    def test_nested_error_1(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "source": {"type": "debug"},
                    "secret": [{"name": "invalid.x"}],
                }
            )

        exc_info.match("source.0.value")
        exc_info.match("secret.0.name")

    def test_nested_error_2(self):
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "source": [
                        {"name": "source-1", "type": "debug", "value": "foobar"},
                        {"name": "source-1", "type": "debug", "value": "bazqax"},
                    ],
                    "secret": [
                        {"name": "dupe-name"},
                        {"name": "dupe-name"},
                    ],
                }
            )

        exc_info.match("source.0.name")
        exc_info.match("source.1.name")
        exc_info.match("secret.0.name")
        exc_info.match("secret.1.name")

    def test_source_name_error_1(self):
        # source not found
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": [],
                    "secret": [
                        {"name": "DEMO", "source": "not-exist"},
                    ],
                }
            )

        exc_info.match("secrets.DEMO.source")
        exc_info.match('source "not-exist" not found')

    def test_source_name_error_2(self):
        # source is None and there are multiple sources
        with pytest.raises(ValidationError) as exc_info:
            LocalConfig.model_validate(
                {
                    "sources": [
                        {"type": "plain", "name": "source-1"},
                        {"type": "plain", "name": "source-2"},
                    ],
                    "secret": [
                        {"name": "FOOBAR"},
                    ],
                }
            )

        exc_info.match("secrets.FOOBAR.source")
        exc_info.match("Field required")


class TestProviderBuilder:

    def test_success(self):
        model = ProviderBuilder.model_validate(
            {
                "source": {"type": "debug:async", "value": "foobar"},
                "sources": [
                    DebugProvider.model_validate({"name": "item2", "value": "foobar"})
                ],
            }
        )

        assert model.source == [IsInstance(AsyncDebugProvider)]
        assert model.sources == [IsInstance(DebugProvider)]

    def test_empty(self):
        model = ProviderBuilder.model_validate({})
        assert model.source == []
        assert model.sources == []

    def test_value_error(self):
        with pytest.raises(ValidationError, match="sources") as exc_info:
            ProviderBuilder.model_validate(
                {
                    "source": [
                        {"name": "item1", "type": "plain"},
                        {"name": "item2", "type": "invalid"},
                    ],
                    "sources": [
                        {"name": "item3", "type": "debug"},
                        {"name": "item4", "type": "plain"},
                    ],
                }
            )

        exc_info.match("source.1.type")
        exc_info.match("sources.0.value")
        exc_info.match("Unknown provider type 'invalid'")

    def test_type_error(self):
        with pytest.raises(ValidationError, match="sources"):
            ProviderBuilder.model_validate({"sources": 1234})

    def test_dupe_name(self):
        with pytest.raises(ValidationError) as exc_info:
            ProviderBuilder.model_validate(
                {
                    "source": [
                        {"name": "item1", "type": "plain"},
                    ],
                    "sources": [
                        {"type": "plain"},
                        {"name": "item1", "type": "plain"},
                    ],
                }
            )

        exc_info.match("source.0.name")
        exc_info.match("sources.1.name")


class TestRequestBuilder:

    def test_success(self):
        model = RequestBuilder.model_validate(
            {
                "secrets": [
                    {"name": "item1", "path": "/path/item1"},
                ],
                "secret": {
                    "item2": {"name": "overwritten"},
                    "item3": "/path/item3",
                    "item4": Request(name="item4"),
                },
            }
        )

        assert model.secrets == [
            Request(name="item1", path="/path/item1"),
        ]
        assert model.secret == [
            Request(name="item2"),
            Request(name="item3", value="/path/item3"),
            Request(name="item4"),
        ]

    def test_error_from_list(self):
        with pytest.raises(ValidationError, match="secret.0.name"):
            RequestBuilder.model_validate(
                {
                    "secret": [{"name": "1nvalid"}],
                }
            )

    def test_error_from_dict(self):
        with pytest.raises(ValidationError, match="secret.1nvalid.name"):
            RequestBuilder.model_validate(
                {
                    "secret": {
                        "1nvalid": {},
                    },
                }
            )

    def test_type_error(self):
        with pytest.raises(ValidationError, match="expect list or dict"):
            RequestBuilder.model_validate({"secret": 1234})

    def test_dupe_name(self):
        with pytest.raises(ValidationError) as exc_info:
            RequestBuilder.model_validate(
                {
                    "secret": [
                        Request(name="item1"),
                    ],
                    "secrets": [
                        Request(name="item1"),
                    ],
                }
            )

        exc_info.match("secret.0.name")
        exc_info.match("secrets.0.name")


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
            Demo.model_validate({"name": 1234, "file": "/not/a/file"})

        assert errors[0]["input"] == 1234
        assert errors[0]["loc"] == ("test", "name")
        assert errors[0]["type"] == "string_type"
        assert errors[1]["input"] == "/not/a/file"
        assert errors[1]["loc"] == ("test", "file")
        assert errors[1]["type"] == "value_error"

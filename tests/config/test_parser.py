import pytest
from pydantic import BaseModel, FilePath, ValidationError

from secrets_env.config.parser import (
    LocalConfig,
    capture_line_errors,
    validate_providers,
    validate_requests,
)
from secrets_env.provider import Request
from secrets_env.providers.plain import PlainTextProvider


class TestValidateProviders:
    def test_success(self):
        values = validate_providers(
            {
                "source": {"name": "item1", "type": "plain"},
                "sources": [PlainTextProvider(name="item2")],
            }
        )

        assert values["providers"] == {
            "item1": PlainTextProvider(name="item1"),
            "item2": PlainTextProvider(name="item2"),
        }

    def test_empty(self):
        values = validate_providers({})
        assert values["providers"] == {}

    def test_value_error(self):
        with pytest.raises(ValidationError, match="sources") as exc_info:
            validate_providers(
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
            validate_providers({"sources": 1234})

    def test_dupe_name(self):
        with pytest.raises(ValidationError, match="duplicated source name"):
            validate_providers(
                {
                    "sources": [
                        {"name": "item1", "type": "plain"},
                        {"name": "item1", "type": "plain"},
                        {"type": "plain"},
                    ],
                }
            )


class TestValidateRequests:
    def test_success(self):
        values = validate_requests(
            {
                "secrets": [
                    {"name": "item1", "path": "/path/item1"},
                ],
                "secret": {
                    "item2": {"name": "overwritten"},
                    "item3": "/path/item3",
                },
            }
        )
        assert values["requests"] == [
            Request(name="item2"),
            Request(name="item3", value="/path/item3"),
            Request(name="item1", path="/path/item1"),
        ]

    def test_dupe_name(self):
        with pytest.raises(ValidationError, match="secrets.item1"):
            validate_requests(
                {
                    "secret": [
                        Request(name="item1"),
                        Request(name="item1"),
                    ]
                }
            )

    def test_error_from_list(self):
        with pytest.raises(ValidationError, match="secret.0.name"):
            validate_requests(
                {
                    "secret": [{"name": "1nvalid"}],
                }
            )

    def test_error_from_dict(self):
        with pytest.raises(ValidationError, match="secret.1nvalid.name"):
            validate_requests(
                {
                    "secret": {
                        "1nvalid": {},
                    },
                }
            )

    def test_type_error(self):
        with pytest.raises(ValidationError, match="expect list or dict"):
            validate_requests({"secret": 1234})


class TestLocalConfig:
    def test_success(self):
        cfg = LocalConfig.model_validate(
            {
                "source": {"name": "source-1", "type": "plain"},
                "secret": {"key1": {"path": "/mock/path"}},
            }
        )

        assert cfg.providers["source-1"] == PlainTextProvider(name="source-1")
        assert cfg.requests[0] == Request(name="key1", path="/mock/path")

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

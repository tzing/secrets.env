import logging
from unittest.mock import Mock, PropertyMock

import pytest

import secrets_env.collect as t
import secrets_env.provider
from secrets_env.exceptions import AuthenticationError, ConfigError
from secrets_env.provider import Request


def test_read_values(caplog: pytest.LogCaptureFixture):
    def create_provider(return_value: str):
        provider = Mock(spec=secrets_env.provider.Provider)
        provider.return_value = return_value
        return provider

    config = {
        "providers": {
            "main": create_provider("main"),
            "p2": create_provider("source-2"),
            "p3": create_provider(None),
        },
        "requests": [
            Request(name="foo", source="main", value="mock"),
            Request(name="bar", source="p2", value="mock"),
            Request(name="baz", source="no-this-provider", value="mock"),
            Request(name="qax", source="main", value="mock"),
            Request(name="wax", source="p3", value="mock"),
        ],
    }

    with caplog.at_level(logging.DEBUG):
        assert t.read_values(config) == {
            "foo": "main",
            "bar": "source-2",
            "qax": "main",
        }

    assert "Read <data>$foo</data> successfully" in caplog.text
    assert "Read <data>$bar</data> successfully" in caplog.text
    assert "Read <data>$qax</data> successfully" in caplog.text

    assert "Failed to read <data>$wax</data>" in caplog.text

    assert (
        "Provider <data>no-this-provider</data> not exists. Skip <data>$baz</data>."
        in caplog.text
    )


class TestRead1:
    def setup_method(self):
        self.provider = Mock(spec=secrets_env.provider.Provider)
        type(self.provider).name = PropertyMock(return_value="mock")

    def test_success(self):
        self.provider.return_value = marker = object()
        assert t.read1(self.provider, "test", "foo#bar") is marker

    def test_input_errors(self):
        with pytest.raises(TypeError):
            t.read1(object(), "test", "foo#bar")

        with pytest.raises(TypeError):
            t.read1(self.provider, object(), "foo#bar")

    def test_auth_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.side_effect = AuthenticationError("test")
        self.provider.type = "mock"

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Authentication error on mock" in caplog.text

    def test_config_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.side_effect = ConfigError("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Config for test is malformed" in caplog.text

    def test_not_found(self, caplog: pytest.LogCaptureFixture):
        self.provider.side_effect = LookupError("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Secret for test not found" in caplog.text

    def test_unknown_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.side_effect = Exception

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Error requesting secret for test" in caplog.text

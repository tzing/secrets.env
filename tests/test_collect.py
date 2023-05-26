from unittest.mock import Mock, PropertyMock

import pytest

import secrets_env.collect as t
import secrets_env.provider
from secrets_env.exceptions import AuthenticationError, ConfigError, ValueNotFound


class TestRead1:
    def setup_method(self):
        self.provider = Mock(spec=secrets_env.provider.ProviderBase)
        type(self.provider).name = PropertyMock(return_value="mock")

    def test_success(self):
        self.provider.get.return_value = marker = object()
        assert t.read1(self.provider, "test", "foo#bar") is marker

    def test_input_errors(self):
        with pytest.raises(TypeError):
            t.read1(object(), "test", "foo#bar")

        with pytest.raises(TypeError):
            t.read1(self.provider, object(), "foo#bar")

        with pytest.raises(TypeError):
            t.read1(self.provider, "test", object())

    def test_auth_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = AuthenticationError("test")
        self.provider.type = "mock"

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Authentication error on mock" in caplog.text

    def test_config_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = ConfigError("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Config for test is malformed" in caplog.text

    def test_not_found(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = ValueNotFound("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Secret for test not found" in caplog.text

    def test_unknown_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = Exception

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Error requesting secret for test" in caplog.text

from unittest.mock import Mock, PropertyMock, patch

import pytest

import secrets_env as t
import secrets_env.exceptions as exps
import secrets_env.types


class TestLoadSecrets:
    @pytest.fixture()
    def provider_1(self):
        provider = Mock(spec=secrets_env.types.ProviderBase)
        provider.get.return_value = "value-1"
        return provider

    @pytest.fixture()
    def provider_2(self):
        provider = Mock(spec=secrets_env.types.ProviderBase)
        provider.get.return_value = "value-2"
        return provider

    def test_success(self, provider_1, provider_2):
        with patch(
            "secrets_env.config.load_config",
            return_value={
                "providers": {"main": provider_1, "another": provider_2},
                "requests": [
                    {"name": "VAR1", "provider": "main", "spec": "foo#bar"},
                    {"name": "VAR2", "provider": "another", "spec": "foo#bar"},
                ],
            },
        ):
            assert t.load_secrets() == {
                "VAR1": "value-1",
                "VAR2": "value-2",
            }

    def test_no_config(self):
        with patch("secrets_env.config.load_config", return_value={}):
            assert t.load_secrets() == {}

    def test_no_provider(self, provider_1):
        with patch(
            "secrets_env.config.load_config",
            return_value={
                "providers": {"main": provider_1},
                "requests": [
                    {"name": "VAR1", "provider": "main", "spec": "foo#bar"},
                    {"name": "VAR2", "provider": "not-exists", "spec": "foo#bar"},
                ],
            },
        ):
            # strict mode - no value return on partial success
            assert t.load_secrets() == {}

    def test_non_strict(self, provider_1, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.config.load_config",
            return_value={
                "providers": {"main": provider_1},
                "requests": [
                    {"name": "VAR1", "provider": "main", "spec": "foo#bar"},
                    {"name": "VAR2", "provider": "not-exists", "spec": "foo#bar"},
                ],
            },
        ):
            assert t.load_secrets(strict=False) == {
                "VAR1": "value-1",
                "VAR2": None,
            }

        assert "<error>1</error> / 2 secrets loaded" in caplog.text


class TestRead1:
    def setup_method(self):
        self.provider = Mock(spec=secrets_env.types.ProviderBase)
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
        self.provider.get.side_effect = exps.AuthenticationError("test")
        self.provider.type = "mock"

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Authentication error on mock" in caplog.text

    def test_config_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = exps.ConfigError("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Config for test is malformed" in caplog.text

    def test_not_found(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = exps.SecretNotFound("test")

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Secret for test not found" in caplog.text

    def test_unknown_error(self, caplog: pytest.LogCaptureFixture):
        self.provider.get.side_effect = Exception

        assert t.read1(self.provider, "test", "foo#bar") is None
        assert "Error requesting secret for test" in caplog.text

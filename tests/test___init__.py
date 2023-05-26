from unittest.mock import Mock, PropertyMock, patch

import pytest

import secrets_env as t
import secrets_env.exceptions as exps
import secrets_env.provider


class TestLoadSecrets:
    @pytest.fixture()
    def provider_1(self):
        provider = Mock(spec=secrets_env.provider.ProviderBase)
        provider.get.return_value = "value-1"
        return provider

    @pytest.fixture()
    def provider_2(self):
        provider = Mock(spec=secrets_env.provider.ProviderBase)
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

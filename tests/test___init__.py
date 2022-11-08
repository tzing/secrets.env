import logging
from unittest.mock import Mock, patch

import pytest

import secrets_env
from secrets_env.auth.token import TokenAuth
from secrets_env.config.types import Config, SecretPath


class TestLoadSecrets:
    @pytest.fixture()
    def patch_load_config(self):
        with patch(
            "secrets_env.config.load_config",
            return_value=Config(
                url="https://example.com/",
                auth=TokenAuth("ex@mp1e"),
                tls={},
                secret_specs={
                    "VAR1": SecretPath("key1", "example"),
                    "VAR2": SecretPath("key2", "example"),
                },
            ),
        ) as mock:
            yield mock

    @pytest.mark.usefixtures("patch_load_config")
    def test_success(self, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.core.KVReader.read_values",
            return_value={
                SecretPath("key1", "example"): "foo",
                SecretPath("key2", "example"): "bar",
            },
        ), caplog.at_level(logging.INFO):
            assert secrets_env.load_secrets(None) == {
                "VAR1": "foo",
                "VAR2": "bar",
            }

        assert "<mark>2</mark> secrets loaded" in caplog.text

    @pytest.mark.usefixtures("patch_load_config")
    def test_partial_loaded(self, caplog: pytest.LogCaptureFixture):
        with patch(
            "secrets_env.core.KVReader.read_values",
            return_value={
                # no key2
                SecretPath("key1", "example"): "foo",
            },
        ):
            assert secrets_env.load_secrets(None) == {"VAR1": "foo"}

        assert "<error>1</error> / 2 secrets loaded" in caplog.text

    def test_no_config(self, patch_load_config: Mock):
        patch_load_config.return_value = None
        assert secrets_env.load_secrets(None) == {}

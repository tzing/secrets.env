from unittest.mock import Mock

import httpx
import pytest
from pydantic_core import Url, ValidationError

import secrets_env.providers.vault.auth.token as t
from secrets_env.providers.vault.auth.token import TokenAuth


class TestTokenAuth:
    def test_create_from_envvar(self, monkeypatch: pytest.MonkeyPatch):
        sample = t.TokenAuth(token="T0ken")

        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_TOKEN", "T0ken")
            assert t.TokenAuth.create(Url("https://example.com/"), {}) == sample

        with monkeypatch.context() as m:
            m.setenv("VAULT_TOKEN", "T0ken")
            assert t.TokenAuth.create(Url("https://example.com/"), {}) == sample

    def test_create_failed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("VAULT_TOKEN", False)
        with pytest.raises(ValidationError, match="Input should be a valid string."):
            assert TokenAuth.create(Url("https://example.com/"), {}) is None

    def test_login(self):
        client = Mock(spec=httpx.Client)
        sample = t.TokenAuth(token="T0ken")
        assert sample.login(client) == "T0ken"

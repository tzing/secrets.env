from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from pydantic_core import Url

import secrets_env.providers.vault.auth.token as t
from secrets_env.providers.vault.auth.token import TokenAuth


class TestTokenAuth:
    @pytest.fixture(autouse=True)
    def _disable_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("VAULT_TOKEN", False)

    @pytest.fixture()
    def _disable_token_helper(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

    def setup_method(self):
        self.sample = t.TokenAuth(token="T0ken")

    def test_create_from_envvar(self, monkeypatch: pytest.MonkeyPatch):
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_TOKEN", "T0ken")
            assert t.TokenAuth.create(Url("https://example.com/"), {}) == self.sample

        with monkeypatch.context() as m:
            m.setenv("VAULT_TOKEN", "T0ken")
            assert t.TokenAuth.create(Url("https://example.com/"), {}) == self.sample

    def test_create_from_helper(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        (tmp_path / ".vault-token").write_text("T0ken")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenAuth.create(Url("https://example.com/"), {}) == self.sample

    @pytest.mark.usefixtures("_disable_token_helper")
    def test_create_failed(self):
        with pytest.raises(ValueError, match="Missing token for Vault authentication."):
            assert TokenAuth.create(Url("https://example.com/"), {}) is None

    def test_login(self):
        client = Mock(spec=httpx.Client)
        assert self.sample.login(client) == "T0ken"

from unittest.mock import Mock

import pytest

import secrets_env.auth
import secrets_env.config.parser as t
from secrets_env.auth import Auth


class TestGetURL:
    def setup_method(self):
        self.data = {"url": "https://data.example.com"}

    def test_from_data(self):
        assert t.get_url(self.data) == "https://data.example.com"

    @pytest.mark.parametrize("var_name", ["SECRETS_ENV_ADDR", "VAULT_ADDR"])
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch, var_name: str):
        monkeypatch.setenv(var_name, "https://env.example.com")
        assert t.get_url(self.data) == "https://env.example.com"

    def test_missing(self, caplog: pytest.LogCaptureFixture):
        assert t.get_url({}) is None
        assert "Missing required config <mark>url</mark>." in caplog.text

    def test_type_error(self):
        assert t.get_url({"url": 1234}) is None


class TestGetAuth:
    @pytest.fixture(autouse=True)
    def _patch_get_auth(self, monkeypatch: pytest.MonkeyPatch):
        def mock_get_auth(method: str, _):
            assert method == "test"
            return Mock(spec=Auth)

        monkeypatch.setattr(secrets_env.auth, "get_auth", mock_get_auth)

    def test_from_data(self):
        assert isinstance(t.get_auth({"method": "test"}), Auth)

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_METHOD", "test")
        assert isinstance(t.get_auth({}), Auth)

    def test_syntax_sugar(self):
        assert isinstance(t.get_auth("test"), Auth)

    def test_no_method(self, caplog: pytest.LogCaptureFixture):
        assert t.get_auth({}) is None
        assert "Missing required config <mark>auth method</mark>." in caplog.text

    def test_type_error(self):
        assert t.get_auth({"method": 1234}) is None

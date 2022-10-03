import pytest

from secrets_env.auth import OktaAuth, TokenAuth, get_auth


class TestGetAuth:
    def test_success_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_TOKEN", "ex@mp1e")
        assert get_auth("TOKEN", {"method": "TOKEN"}) == TokenAuth("ex@mp1e")

    def test_success_okta(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "foo")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "bar")
        assert get_auth("okta", {}) == OktaAuth("foo", "bar")

    def test_fail(self, caplog: pytest.LogCaptureFixture):
        assert getattr("no-this-method", {})
        assert "Unknown auth method: <data>no-this-method</data>" in caplog.text

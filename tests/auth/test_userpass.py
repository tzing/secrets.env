from unittest.mock import patch

import httpx
import pytest
import respx

import secrets_env.auth.userpass as t


class TestUserPasswordAuth:
    @pytest.fixture(autouse=True)
    def _patch_userpass(self, monkeypatch: pytest.MonkeyPatch):
        # UserPasswordAuth does not implemented all the required methods so need
        # to patch __abstractmethods__ to skip TypeError raised by ABC
        monkeypatch.setattr(t.UserPasswordAuth, "__abstractmethods__", set())
        monkeypatch.setattr(t.UserPasswordAuth, "method", lambda: "MOCK")

    def test___init__(self):
        # success
        obj = t.UserPasswordAuth("user@example.com", "P@ssw0rd")
        assert obj.username == "user@example.com"
        assert obj.password == "P@ssw0rd"

        # error
        with pytest.raises(TypeError):
            t.UserPasswordAuth(1234, "P@ssw0rd")
        with pytest.raises(TypeError):
            t.UserPasswordAuth("user@example.com", 1234)

    def test_load_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t.UserPasswordAuth, "_load_username", lambda _: "user")
        monkeypatch.setattr(t.UserPasswordAuth, "_load_password", lambda: "P@ssw0rd")

        obj = t.UserPasswordAuth.load({})
        assert obj == t.UserPasswordAuth("user", "P@ssw0rd")

    @pytest.mark.parametrize(
        ("username", "password"),
        [
            ("user@example.com", ""),
            ("", "P@ssw0rd"),
            ("user@example.com", None),
            (None, "P@ssw0rd"),
        ],
    )
    def test_load_fail(
        self,
        username: str,
        password: str,
        caplog: pytest.LogCaptureFixture,
    ):
        with patch.object(
            t.UserPasswordAuth, "_load_username", return_value=username
        ), patch.object(t.UserPasswordAuth, "_load_password", return_value=password):
            assert t.UserPasswordAuth.load({}) is None

        assert any(
            (
                "Missing username for MOCK auth." in caplog.text,
                "Missing password for MOCK auth." in caplog.text,
            )
        )

    def test__load_username(self, monkeypatch: pytest.MonkeyPatch):
        # config
        assert t.UserPasswordAuth._load_username({"username": "foo"}) == "foo"

        # env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_USERNAME", "foo")
            assert t.UserPasswordAuth._load_username({}) == "foo"

        # prompt
        with patch.object(t, "prompt", return_value="foo") as p:
            assert t.UserPasswordAuth._load_username({}) == "foo"
            p.assert_any_call("Username for MOCK auth")

        # keyring
        with patch.object(t, "read_keyring", return_value="foo") as r:
            assert t.UserPasswordAuth._load_username({}) == "foo"
            r.assert_any_call("MOCK/username")

    def test__load_password(self, monkeypatch: pytest.MonkeyPatch):
        # env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_PASSWORD", "bar")
            assert t.UserPasswordAuth._load_password() == "bar"

        # prompt
        with patch.object(t, "prompt", return_value="bar") as p:
            assert t.UserPasswordAuth._load_password() == "bar"
            p.assert_any_call("Password", hide_input=True)

        # keyring
        with patch.object(t, "read_keyring", return_value="bar") as r:
            assert t.UserPasswordAuth._load_password() == "bar"
            r.assert_any_call("MOCK/password")


class TestOktaAuth:
    def setup_method(self):
        self.authobj = t.OktaAuth("user", "pass")

    def test__init__(self):
        assert self.authobj.username == "user"
        assert self.authobj.password == "pass"

    def test__repr__(self):
        assert repr(self.authobj) == "OktaAuth(username='user')"

    def test_method(self):
        assert t.OktaAuth.method() == "okta"

    def test_login_success(self, respx_mock: respx.MockRouter):
        respx_mock.post("http://example.com/v1/auth/okta/login/user").mock(
            return_value=httpx.Response(
                200,
                json={
                    "lease_id": "",
                    "renewable": False,
                    "lease_duration": 0,
                    "data": None,
                    "warnings": None,
                    "auth": {
                        "client_token": "64d2a8f2-2a2f-5688-102b-e6088b76e344",
                        "accessor": "18bb8f89-826a-56ee-c65b-1736dc5ea27d",
                        "policies": ["default"],
                        "metadata": {"username": "fred", "policies": "default"},
                        "lease_duration": 7200,
                        "renewable": True,
                    },
                },
            )
        )

        client = httpx.Client(base_url="http://example.com")
        assert self.authobj.login(client) == "64d2a8f2-2a2f-5688-102b-e6088b76e344"

    def test_login_fail(self, respx_mock: respx.MockRouter):
        respx_mock.post("http://example.com/v1/auth/okta/login/user").mock(
            return_value=httpx.Response(403)
        )

        client = httpx.Client(base_url="http://example.com")
        assert self.authobj.login(client) is None

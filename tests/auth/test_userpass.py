from unittest.mock import patch

import httpx
import pytest
import respx

import secrets_env.auth.userpass as t


@pytest.fixture()
def login_success_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": None,
            "warnings": None,
            "auth": {
                "client_token": "client-token",
                "accessor": "accessor-token",
                "policies": ["default"],
                "metadata": {"username": "fred", "policies": "default"},
                "lease_duration": 7200,
                "renewable": True,
            },
        },
    )


class TestUserPasswordAuth:
    @pytest.fixture(autouse=True)
    def _unfreeze_userpass(self, monkeypatch: pytest.MonkeyPatch):
        # UserPasswordAuth does not implemented all the required methods so need
        # to patch __abstractmethods__ to skip TypeError raised by ABC
        monkeypatch.setattr(t.UserPasswordAuth, "__abstractmethods__", set())

    @pytest.fixture()
    def _patch_method(self):
        with patch.object(t.UserPasswordAuth, "method", return_value="MOCK"):
            yield

    @pytest.fixture()
    def _patch_path(self):
        with patch.object(t.UserPasswordAuth, "path", return_value="mock"):
            yield

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

    def test_path(self):
        with pytest.raises(NotImplementedError):
            t.UserPasswordAuth.path()

    def test_load_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(t.UserPasswordAuth, "_load_username", lambda _: "user")
        monkeypatch.setattr(t.UserPasswordAuth, "_load_password", lambda _: "P@ssw0rd")

        obj = t.UserPasswordAuth.load({})
        assert obj == t.UserPasswordAuth("user", "P@ssw0rd")

    @pytest.mark.usefixtures("_patch_method")
    @pytest.mark.parametrize(
        ("username", "password", "err_message"),
        [
            ("user@example.com", "", "Missing password for MOCK auth."),
            ("", "P@ssw0rd", "Missing username for MOCK auth."),
            ("user@example.com", None, "Missing password for MOCK auth."),
            (None, "P@ssw0rd", "Missing username for MOCK auth."),
        ],
    )
    def test_load_fail(
        self,
        monkeypatch: pytest.MonkeyPatch,
        username: str,
        password: str,
        caplog: pytest.LogCaptureFixture,
        err_message: str,
    ):
        monkeypatch.setattr(t.UserPasswordAuth, "_load_username", lambda _: username)
        monkeypatch.setattr(t.UserPasswordAuth, "_load_password", lambda _: password)
        assert t.UserPasswordAuth.load({}) is None
        assert err_message in caplog.text

    @pytest.mark.usefixtures("_patch_method")
    @pytest.mark.usefixtures("_patch_path")
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
            r.assert_any_call("mock/:username")

    @pytest.mark.usefixtures("_patch_path")
    def test__load_password(self, monkeypatch: pytest.MonkeyPatch):
        # env var
        with monkeypatch.context() as m:
            m.setenv("SECRETS_ENV_PASSWORD", "bar")
            assert t.UserPasswordAuth._load_password("foo") == "bar"

        # prompt
        with patch.object(t, "prompt", return_value="bar") as p:
            assert t.UserPasswordAuth._load_password("foo") == "bar"
            p.assert_any_call("Password for foo", hide_input=True)

        # keyring
        with patch.object(t, "read_keyring", return_value="bar") as r:
            assert t.UserPasswordAuth._load_password("foo") == "bar"
            r.assert_any_call("mock/foo")

    @pytest.mark.usefixtures("_patch_path")
    def test_login_success(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/mock/login/user%40example.com").mock(
            return_value=login_success_response
        )

        auth_obj = t.UserPasswordAuth("user@example.com", "password")
        assert auth_obj.login(unittest_client) == "client-token"

    @pytest.mark.usefixtures("_patch_method")
    @pytest.mark.usefixtures("_patch_path")
    def test_login_fail(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        caplog: pytest.LogCaptureFixture,
    ):
        unittest_respx.post("/v1/auth/mock/login/user%40example.com").mock(
            return_value=httpx.Response(400)
        )

        auth_obj = t.UserPasswordAuth("user@example.com", "password")
        assert auth_obj.login(unittest_client) is None

        assert "Failed to login with MOCK method" in caplog.text


class TestBasicAuth:
    def test_method(self):
        assert t.BasicAuth.method() == "basic"

    def test_login(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/userpass/login/user%40basic.example.com").mock(
            return_value=login_success_response
        )
        authobj = t.BasicAuth("user@basic.example.com", "pass")
        assert authobj.login(unittest_client) == "client-token"

    def test_load(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "user")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")
        assert t.BasicAuth.load({}) == t.BasicAuth("user", "pass")


class TestOktaAuth:
    def test_method(self):
        assert t.OktaAuth.method() == "Okta"

    def test_login(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/okta/login/user%40okta.example.com").mock(
            return_value=login_success_response
        )
        auth_obj = t.OktaAuth("user@okta.example.com", "pass")
        assert auth_obj.login(unittest_client) == "client-token"

    def test_load(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "user@okta.example.com")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")
        assert t.OktaAuth.load({}) == t.OktaAuth("user@okta.example.com", "pass")


class TestLDAP:
    def test_method(self):
        assert t.LDAPAuth.method() == "LDAP"

    def test_login(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/ldap/login/user%40ldap.example.com").mock(
            return_value=login_success_response
        )
        auth_obj = t.LDAPAuth("user@ldap.example.com", "pass")
        assert auth_obj.login(unittest_client) == "client-token"

    def test_load(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "user@ldap.example.com")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")
        assert t.LDAPAuth.load({}) == t.LDAPAuth("user@ldap.example.com", "pass")


class TestRADIUS:
    def test_method(self):
        assert t.RADIUSAuth.method() == "RADIUS"

    def test_login(
        self,
        unittest_respx: respx.MockRouter,
        unittest_client: httpx.Client,
        login_success_response: httpx.Response,
    ):
        unittest_respx.post("/v1/auth/radius/login/user%40pap.example.com").mock(
            return_value=login_success_response
        )
        auth_obj = t.RADIUSAuth("user@pap.example.com", "pass")
        assert auth_obj.login(unittest_client) == "client-token"

    def test_load(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SECRETS_ENV_USERNAME", "user@pap.example.com")
        monkeypatch.setenv("SECRETS_ENV_PASSWORD", "pass")
        assert t.RADIUSAuth.load({}) == t.RADIUSAuth("user@pap.example.com", "pass")

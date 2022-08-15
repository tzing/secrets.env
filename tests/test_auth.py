from unittest.mock import Mock, mock_open, patch

import click
import hvac
import keyring.errors
import pytest

from secrets_env import auth


def test_read_keyring():
    with patch("keyring.get_password", return_value="bar"):
        assert auth.read_keyring("foo") == "bar"
    with patch("keyring.get_password", side_effect=keyring.errors.NoKeyringError()):
        assert auth.read_keyring("foo") is None


@pytest.fixture()
def patch_read_keyring():
    with patch("secrets_env.auth.read_keyring", return_value=None) as m:
        yield m


class TestPrompt:
    def test_no_click(self):
        with patch(
            "importlib.import_module",
            side_effect=ImportError("Mock import error"),
        ):
            assert auth.prompt("test") is None

    @patch.dict("os.environ", {"SECRETS_ENV_NO_PROMPT": "True"})
    def test_disable(self):
        assert auth.prompt("test") is None

    @patch.dict("os.environ", {"SECRETS_ENV_NO_PROMPT": "Foo"})
    def test_success(self):
        with patch("click.prompt", return_value="buzz"):
            assert auth.prompt("test") == "buzz"

    def test_abort(self):
        with patch("click.prompt", side_effect=click.Abort("mock abort")):
            assert auth.prompt("test") is None


class TestTokenAuth:
    @pytest.fixture()
    def toke_helper_file(self):
        with patch("pathlib.Path.home") as home:
            # Hardcoded path to match the path:
            #   pathlib.Path.home() / ".vault-token"
            path = home.return_value.__truediv__.return_value
            path.is_file.return_value = False
            yield path

    def setup_method(self):
        self.obj = auth.TokenAuth("T0ken")

    def test__init__(self):
        assert self.obj.method() == "token"
        assert self.obj.token == "T0ken"

        with pytest.raises(TypeError):
            auth.TokenAuth(1234)

    def test__repr__(self):
        assert repr(self.obj) == "TokenAuth(token='T0ken')"

    def test_method(self):
        assert auth.TokenAuth.method() == "token"

    def test_apply(self):
        # set up token doesn't trigger connection, so uses real client
        client = hvac.Client("https://example.com")
        self.obj.apply(client)
        assert client.token == "T0ken"

    def test_load_env_var(self):
        with patch.dict("os.environ", {"VAULT_TOKEN": "foo"}):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

        with patch.dict("os.environ", {"SECRETS_ENV_TOKEN": "foo"}):
            assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

    def test_load_helper(self, toke_helper_file: Mock):
        toke_helper_file.is_file.return_value = True
        toke_helper_file.open = mock_open(read_data="foo\n")
        assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

    @pytest.mark.usefixtures("toke_helper_file")
    def test_load_keyring(self, patch_read_keyring: Mock):
        patch_read_keyring.return_value = "foo"
        assert auth.TokenAuth.load({}) == auth.TokenAuth("foo")

    @pytest.mark.usefixtures("toke_helper_file")
    @pytest.mark.usefixtures("patch_read_keyring")
    def test_load_fail(self):
        assert auth.TokenAuth.load({}) is None


class TestUserPasswordAuth:
    def setup_method(self):
        # UserPasswordAuth has some required abstract method not implemented.
        # Use this fixture to patch the propertires for running the test.
        self.patches = [
            patch.object(auth.UserPasswordAuth, "__abstractmethods__", set()),
            patch.object(auth.UserPasswordAuth, "method", return_value="mock"),
        ]

        for p in self.patches:
            p.start()

    def teardown_method(self):
        for p in self.patches:
            p.stop()

    def test___init__(self):
        # success
        obj = auth.UserPasswordAuth("user@example.com", "P@ssw0rd")
        assert obj.username == "user@example.com"
        assert obj.password == "P@ssw0rd"

        # error
        with pytest.raises(TypeError):
            auth.UserPasswordAuth(1234, "P@ssw0rd")
        with pytest.raises(TypeError):
            auth.UserPasswordAuth("user@example.com", 1234)

    def test_load_success(self):
        with patch.object(
            auth.UserPasswordAuth, "_load_username", return_value="user@example.com"
        ), patch.object(
            auth.UserPasswordAuth, "_load_password", return_value="P@ssw0rd"
        ):
            obj = auth.UserPasswordAuth.load({})
        assert obj == auth.UserPasswordAuth("user@example.com", "P@ssw0rd")

    @pytest.mark.parametrize(
        ("username", "password"),
        [
            ("user@example.com", ""),
            ("", "P@ssw0rd"),
            ("user@example.com", None),
            (None, "P@ssw0rd"),
        ],
    )
    def test_load_failed(
        self, username: str, password: str, caplog: pytest.LogCaptureFixture
    ):
        with patch.object(
            auth.UserPasswordAuth, "_load_username", return_value=username
        ), patch.object(auth.UserPasswordAuth, "_load_password", return_value=password):
            assert auth.UserPasswordAuth.load({}) is None

        assert any(
            (
                "Missing username for mock auth." in caplog.text,
                "Missing password for mock auth." in caplog.text,
            )
        )

    def test__load_username(self):
        # env var
        with patch.dict("os.environ", {"SECRETS_ENV_USERNAME": "foo"}):
            assert auth.UserPasswordAuth._load_username({}) == "foo"

        # config
        assert auth.UserPasswordAuth._load_username({"username": "foo"}) == "foo"

        # keyring
        with patch("secrets_env.auth.read_keyring", return_value="foo") as g:
            assert auth.UserPasswordAuth._load_username({}) == "foo"
            g.assert_any_call("mock/:username")

        # prompt
        with patch("secrets_env.auth.read_keyring", return_value=None), patch(
            "secrets_env.auth.prompt", return_value="foo"
        ):
            assert auth.UserPasswordAuth._load_username({}) == "foo"

    def test__load_password(self):
        # env var
        with patch.dict("os.environ", {"SECRETS_ENV_PASSWORD": "bar"}):
            assert auth.UserPasswordAuth._load_password("foo") == "bar"

        # keyring
        with patch("secrets_env.auth.read_keyring", return_value="bar") as g:
            assert auth.UserPasswordAuth._load_password("foo") == "bar"
            g.assert_any_call("mock/foo")

        # prompt
        with patch("secrets_env.auth.read_keyring", return_value=None), patch(
            "secrets_env.auth.prompt", return_value="bar"
        ):
            assert auth.UserPasswordAuth._load_password("foo") == "bar"


class TestOktaAuth:
    def setup_method(self):
        self.obj = auth.OktaAuth("user", "pass")

    def test__init__(self):
        assert self.obj.username == "user"
        assert self.obj.password == "pass"

    def test__repr__(self):
        assert repr(self.obj) == "OktaAuth(username='user')"

    def test_method(self):
        assert auth.OktaAuth.method() == "okta"

    def test_apply(self):
        client = Mock(spec=hvac.Client)

        self.obj.apply(client)
        assert client.auth.okta.login.call_count == 1

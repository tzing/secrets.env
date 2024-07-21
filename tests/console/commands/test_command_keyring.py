from unittest.mock import patch

import click.testing
import keyring.backends.fail
import keyring.backends.null
import keyring.errors
import pytest
from pydantic_core import Url

import secrets_env.console.commands.keyring
from secrets_env.console.commands.keyring import (
    UrlParam,
    assert_keyring_available,
    group,
)


@pytest.fixture()
def _assume_keyring_available(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        secrets_env.console.commands.keyring, "assert_keyring_available", lambda: None
    )


def test_url_param():
    pt = UrlParam()
    assert pt("https://example.com") == Url("https://example.com/")
    assert pt("EXAMPLE.COM") == Url("https://EXAMPLE.COM/")


class TestSet:
    @pytest.mark.usefixtures("_assume_keyring_available")
    @pytest.mark.usefixtures("_reset_logging")
    def test_success_1(self, monkeypatch: pytest.MonkeyPatch):
        def _set_password(svc, user, passwd):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'
            assert passwd == "P@ssw0rd"

        monkeypatch.setattr("keyring.set_password", _set_password)

        runner = click.testing.CliRunner()
        rv = runner.invoke(
            group, ["set", "https://example.com", "test", "-p", "P@ssw0rd"]
        )

        assert rv.exit_code == 0

    @pytest.mark.usefixtures("_assume_keyring_available")
    @pytest.mark.usefixtures("_reset_logging")
    def test_success_2(self, monkeypatch: pytest.MonkeyPatch):
        def _set_password(svc, user, passwd):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'
            assert passwd == "P@ssw0rd"

        monkeypatch.setattr("keyring.set_password", _set_password)

        runner = click.testing.CliRunner()
        rv = runner.invoke(
            group,
            ["set", "https://example.com", "test", "--password-stdin"],
            input="P@ssw0rd\n",
        )

        assert rv.exit_code == 0

    @pytest.mark.usefixtures("_reset_logging")
    def test_invalid_args(self):
        runner = click.testing.CliRunner()

        rv = runner.invoke(group, ["set", "example.com", "test"])
        assert rv.exit_code == 2

        rv = runner.invoke(
            group, ["set", "example.com", "test", "-p", "P@ssw0rd", "--password-stdin"]
        )
        assert rv.exit_code == 2

    @pytest.mark.usefixtures("_assume_keyring_available")
    @pytest.mark.usefixtures("_reset_logging")
    def test_keyring_error(self, monkeypatch: pytest.MonkeyPatch):
        def _set_password(svc, user, passwd):
            raise keyring.errors.PasswordSetError

        monkeypatch.setattr("keyring.set_password", _set_password)

        runner = click.testing.CliRunner()
        rv = runner.invoke(
            group, ["set", "https://example.com", "test", "-p", "P@ssw0rd"]
        )

        assert rv.exit_code == 1
        assert "Failed to save password" in rv.stdout


class TestDel:
    @pytest.mark.usefixtures("_assume_keyring_available")
    @pytest.mark.usefixtures("_reset_logging")
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        def _del_password(svc, user):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'

        monkeypatch.setattr("keyring.delete_password", _del_password)

        runner = click.testing.CliRunner()
        rv = runner.invoke(group, ["del", "https://example.com", "test"])

        assert rv.exit_code == 0
        assert "Password removed" in rv.stdout

    @pytest.mark.usefixtures("_assume_keyring_available")
    @pytest.mark.usefixtures("_reset_logging")
    def test_error(self, monkeypatch: pytest.MonkeyPatch):
        def _del_password(svc, user):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'
            raise keyring.errors.PasswordDeleteError

        monkeypatch.setattr("keyring.delete_password", _del_password)

        runner = click.testing.CliRunner()
        rv = runner.invoke(group, ["del", "https://example.com", "test"])

        assert rv.exit_code == 0
        assert "Password not found" in rv.stdout


def test_assert_keyring_available():
    # success
    with patch("keyring.get_keyring", return_value=keyring.backends.null.Keyring()):
        assert assert_keyring_available() is None

    # test import error
    with (
        patch.dict("sys.modules", {"keyring": None}),
        pytest.raises(click.Abort),
    ):
        assert_keyring_available()

    # keyring unavailable
    with (
        patch("keyring.get_keyring", return_value=keyring.backends.fail.Keyring()),
        pytest.raises(click.Abort),
    ):
        assert_keyring_available()

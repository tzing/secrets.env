import functools
import sys
from unittest.mock import Mock

import click
import click.testing
import keyring.backends.fail
import keyring.backends.null
import keyring.errors
import pytest
from pydantic_core import Url

from secrets_env.console.commands.set import (
    UrlParam,
    UserInputOption,
    VisibleOption,
    assert_keyring_available,
    group_set,
)


class TestVisibleOption:
    def test_usage(self):
        @click.command()
        @click.option(
            "--choice",
            cls=VisibleOption,
            type=click.Choice(["a", "b", "c"]),
        )
        @click.option(
            "--string",
            cls=VisibleOption,
        )
        def demo(): ...

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, ["--help"])

        assert result.exit_code == 0

        usage = result.output.splitlines()[0]
        assert "Usage:" in usage
        assert "--choice [a|b|c]" in usage
        assert "--string TEXT" in usage


class TestUserInputOption:
    @pytest.fixture()
    def basic_invoker(self):
        @click.command()
        @click.option("-v", "--value", cls=UserInputOption)
        def demo(value: str):
            assert value == "test"

        runner = click.testing.CliRunner()
        return functools.partial(runner.invoke, demo)

    def test_consume_value__commandline(self, basic_invoker):
        result = basic_invoker(["-v", "test"])
        assert result.exit_code == 0

    def test_consume_value__stdin(self, basic_invoker):
        result = basic_invoker(["-v", "-"], input="test")
        assert result.exit_code == 0

    def test_consume_value__prompt(self):
        @click.command()
        @click.option("-v", "--value", required=True, cls=UserInputOption)
        def demo(value: str):
            assert value == "test"

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, input="test")

        assert result.exit_code == 0

    def test_consume_value__prompt_skip(self):
        @click.command()
        @click.option("-v", "--value", cls=UserInputOption)
        def demo(value):
            assert value is None

        runner = click.testing.CliRunner()
        result = runner.invoke(demo)

        assert result.exit_code == 0


class TestUrlParam:
    @pytest.mark.parametrize(
        "arg",
        [
            "EXAMPLE.COM",
            "https://example.com",
            "http://example.com/path/to/resource",
        ],
    )
    def test_convert(self, arg: str):
        @click.command()
        @click.argument("url", type=UrlParam())
        def demo(url: Url):
            assert url.host == "example.com"

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, [arg])

        assert result.exit_code == 0

    def test_convert_error(self):
        @click.command()
        @click.argument("url", type=UrlParam())
        def demo(url: str): ...

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, ["test"])

        assert result.exit_code == 2


class TestSetPassword:
    @pytest.fixture(autouse=True)
    def _assume_keyring_available(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.console.commands.set.assert_keyring_available", lambda: None
        )

    def test_set__success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_set(svc, user, passwd):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'
            assert passwd == "P@ssw0rd"

        monkeypatch.setattr("keyring.set_password", mock_set)

        runner = click.testing.CliRunner()
        result = runner.invoke(
            group_set,
            ["password", "-t", "https://example.com", "-u", "test", "-p", "-"],
            input="P@ssw0rd\n",
        )

        assert result.exit_code == 0
        assert "Password saved" in result.output

    def test_set__error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.set_password",
            Mock(side_effect=keyring.errors.PasswordSetError),
        )

        runner = click.testing.CliRunner()
        result = runner.invoke(
            group_set,
            ["password", "-t", "https://example.com", "-u", "test", "-p", "P@ssw0rd"],
        )

        assert result.exit_code == 1
        assert "Failed to save password" in result.output

    def test_remove__success(self, monkeypatch: pytest.MonkeyPatch):
        def mock_delete(svc, user):
            assert svc == "secrets.env"
            assert user == '{"host": "example.com", "type": "login", "user": "test"}'

        monkeypatch.setattr("keyring.delete_password", mock_delete)

        runner = click.testing.CliRunner()
        result = runner.invoke(
            group_set, ["password", "-t", "https://example.com", "-u", "test", "-d"]
        )

        assert result.exit_code == 0
        assert "Password removed" in result.output

    def test_remove__not_exist(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.delete_password",
            Mock(side_effect=keyring.errors.PasswordDeleteError),
        )

        runner = click.testing.CliRunner()
        result = runner.invoke(
            group_set, ["password", "-t", "https://example.com", "-u", "test", "-d"]
        )

        assert result.exit_code == 0
        assert "Password removed" in result.output


class TestAssertKeyringAvailable:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.get_keyring", lambda: keyring.backends.null.Keyring()
        )
        assert assert_keyring_available() is None

    def test_import_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setitem(sys.modules, "keyring", None)
        with pytest.raises(click.Abort):
            assert_keyring_available()

    def test_keyring_unavailable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.get_keyring", lambda: keyring.backends.fail.Keyring()
        )
        with pytest.raises(click.Abort):
            assert_keyring_available()

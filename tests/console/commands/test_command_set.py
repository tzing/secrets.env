import click
import click.testing
import keyring.backends.fail
import keyring.backends.null
import keyring.errors
import pytest

from secrets_env.console.commands.set import (
    HostParam,
    VisibleOption,
    assert_keyring_available,
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


class TestHostParam:
    @pytest.mark.parametrize(
        "arg",
        [
            "EXAMPLE.COM",
            "https://example.com",
            "http://example.com",
        ],
    )
    def test_convert(self, arg: str):
        @click.command()
        @click.argument("host", type=HostParam())
        def demo(host: str):
            assert host == "example.com"

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, [arg])

        assert result.exit_code == 0

    def test_convert_error(self):
        @click.command()
        @click.argument("host", type=HostParam())
        def demo(host: str): ...

        runner = click.testing.CliRunner()
        result = runner.invoke(demo, ["test"])

        assert result.exit_code == 2


class TestAssertKeyringAvailable:
    def test_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.get_keyring", lambda: keyring.backends.null.Keyring()
        )
        assert assert_keyring_available() is None

    def test_import_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("sys.modules", {"keyring": None})
        with pytest.raises(click.Abort):
            assert_keyring_available()

    def test_keyring_unavailable(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "keyring.get_keyring", lambda: keyring.backends.fail.Keyring()
        )
        with pytest.raises(click.Abort):
            assert_keyring_available()

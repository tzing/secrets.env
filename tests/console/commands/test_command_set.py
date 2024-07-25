import click
import click.testing
import pytest

from secrets_env.console.commands.set import HostParam, VisibleOption, group_set


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

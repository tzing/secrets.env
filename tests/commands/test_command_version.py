import click.testing

import secrets_env.commands.version as t


def test():
    runner = click.testing.CliRunner()
    result = runner.invoke(t.version)
    assert result.exit_code == 0

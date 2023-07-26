import click.testing

import secrets_env.commands.completion as t


def test():
    runner = click.testing.CliRunner()
    result = runner.invoke(t.completion)
    assert result.exit_code == 0

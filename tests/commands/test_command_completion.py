import os

import click.testing
import pytest

import secrets_env.commands.completion as t


@pytest.mark.skipif(
    os.path.basename(os.environ.get("SHELL", "")) not in ("bash", "zsh"),
    reason="Shell completion is not avaliable in current shell",
)
def test():
    runner = click.testing.CliRunner()
    result = runner.invoke(t.completion)
    assert result.exit_code == 0
    assert "#compdef secrets.env" in result.stdout

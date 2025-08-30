import os

import click.testing
import pytest

from secrets_env.console.commands.completion import completion


@pytest.mark.skipif(
    os.path.basename(os.environ.get("SHELL", "")) not in ("bash", "zsh"),
    reason="Shell completion is not avaliable in current shell",
)
def test():
    runner = click.testing.CliRunner()
    result = runner.invoke(completion)
    assert result.exit_code == 0
    assert "_secretsenv_completion()" in result.stdout

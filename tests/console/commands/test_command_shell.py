from unittest.mock import Mock

import click.testing
import pytest

from secrets_env.console.commands.shell import shell
from secrets_env.console.shells.base import Shell
from secrets_env.exceptions import ConfigError


@pytest.mark.usefixtures("_reset_logging")
def test_success(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {"foo": "bar"}

    def mock_get_shell():
        mock_shell = Mock(Shell)
        mock_shell.activate.side_effect = SystemExit()
        return mock_shell

    monkeypatch.setattr("secrets_env.load_values_sync", mock_read_values)
    monkeypatch.setattr("secrets_env.console.shells.get_shell", mock_get_shell)

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)
    assert result.exit_code == 0


@pytest.mark.usefixtures("_reset_logging")
def test_nested(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_ACTIVE", "1")

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 1


@pytest.mark.usefixtures("_reset_logging")
def test_read_values_error(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        raise ConfigError("test error")

    monkeypatch.setattr("secrets_env.load_values_sync", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 1
    assert "test error" in result.output


@pytest.mark.usefixtures("_reset_logging")
def test_no_value(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {}

    monkeypatch.setattr("secrets_env.load_values_sync", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 0
    assert "No values found" in result.output

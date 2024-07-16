from unittest.mock import Mock

import click.testing
import pytest

from secrets_env.console.commands.shell import shell
from secrets_env.console.shells.base import Shell
from secrets_env.exceptions import ConfigError


@pytest.fixture()
def _mock_read_values(monkeypatch: pytest.MonkeyPatch):
    def func(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.read_values", func)


@pytest.fixture()
def _mock_get_shell(monkeypatch: pytest.MonkeyPatch):
    def func():
        mock_shell = Mock(Shell)
        mock_shell.activate.side_effect = SystemExit()
        return mock_shell

    monkeypatch.setattr("secrets_env.console.shells.get_shell", func)


@pytest.mark.usefixtures("_reset_logging")
@pytest.mark.usefixtures("_mock_read_values")
@pytest.mark.usefixtures("_mock_get_shell")
def test_success():
    runner = click.testing.CliRunner()
    result = runner.invoke(shell)
    assert result.exit_code == 0


@pytest.mark.usefixtures("_reset_logging")
def test_nested(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_ACTIVE", "1")

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 3


@pytest.mark.usefixtures("_reset_logging")
@pytest.mark.usefixtures("_mock_read_values")
@pytest.mark.usefixtures("_mock_get_shell")
def test_warning_poetry(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("POETRY_ACTIVE", "1")

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 0
    assert "Detected Poetry environment" in result.output


@pytest.mark.usefixtures("_reset_logging")
@pytest.mark.usefixtures("_mock_read_values")
@pytest.mark.usefixtures("_mock_get_shell")
def test_warning_virtualenv(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("POETRY_ACTIVE", raising=False)
    monkeypatch.setenv("VIRTUAL_ENV", "1")

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 0
    assert "Detected Python virtual environment" in result.output


@pytest.mark.usefixtures("_reset_logging")
def test_read_values_error(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        raise ConfigError("test error")

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 2
    assert "test error" in result.output


@pytest.mark.usefixtures("_reset_logging")
def test_no_value(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(shell)

    assert result.exit_code == 0
    assert "No values found" in result.output
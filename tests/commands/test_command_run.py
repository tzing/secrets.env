import click.testing
import pytest

from secrets_env.commands.run import run
from secrets_env.exceptions import ConfigError


def test_success(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 0


def test_program_fail(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "sh", "-c", "exit 33"])

    assert result.exit_code == 33


def test_config_empty(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 0


def test_config_error(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        raise ConfigError

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 1

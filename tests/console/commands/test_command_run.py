import click.testing
import pytest

from secrets_env.console.commands.run import run
from secrets_env.exceptions import ConfigError


@pytest.mark.usefixtures("_reset_logging")
def test_success(monkeypatch: pytest.MonkeyPatch):
    def _load_values_sync(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.load_values_sync", _load_values_sync)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 0


def test_usage():
    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--help"])
    assert "Usage: run [OPTIONS] [--] COMMAND [ARGS]..." in result.output


@pytest.mark.usefixtures("_reset_logging")
def test_program_fail(monkeypatch: pytest.MonkeyPatch):
    def _load_values_sync(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.load_values_sync", _load_values_sync)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "sh", "-c", "exit 33"])

    assert result.exit_code == 33


@pytest.mark.usefixtures("_reset_logging")
def test_config_empty(monkeypatch: pytest.MonkeyPatch):
    def _load_values_sync(config, strict):
        return {}

    monkeypatch.setattr("secrets_env.load_values_sync", _load_values_sync)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 0


@pytest.mark.usefixtures("_reset_logging")
def test_config_error(monkeypatch: pytest.MonkeyPatch):
    def _load_values_sync(config, strict):
        raise ConfigError

    monkeypatch.setattr("secrets_env.load_values_sync", _load_values_sync)

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 1


@pytest.mark.usefixtures("_reset_logging")
def test_recursive_activation(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRETS_ENV_ACTIVE", "1")

    runner = click.testing.CliRunner()
    result = runner.invoke(run, ["--", "echo"])

    assert result.exit_code == 1
    assert "secrets.env is already active" in result.output

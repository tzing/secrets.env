import click.testing
import pytest

import secrets_env.commands.run as t


def test_success(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(t.run, ["--", "echo"])

    assert result.exit_code == 0


def test_program_fail(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {"foo": "bar"}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(t.run, ["--", "sh", "-c", "exit 33"])

    assert result.exit_code == 33


def test_config_empty(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return {}

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(t.run, ["--", "echo"])

    assert result.exit_code == 0


def test_config_error(monkeypatch: pytest.MonkeyPatch):
    def mock_read_values(config, strict):
        return None

    monkeypatch.setattr("secrets_env.read_values", mock_read_values)

    runner = click.testing.CliRunner()
    result = runner.invoke(t.run, ["--", "echo"])

    assert result.exit_code == 128

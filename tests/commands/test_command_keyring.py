from unittest.mock import patch

import click.testing
import keyring.backends.fail
import keyring.backends.null
import keyring.errors
import pytest

import secrets_env.commands.keyring as t


@pytest.fixture()
def _patch_is_keyring_available(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(t, "is_keyring_available", lambda: True)


def test_status():
    runner = click.testing.CliRunner()

    with patch.object(t, "is_keyring_available", return_value=True):
        assert runner.invoke(t.group, ["status"]).exit_code == 0

    with patch.object(t, "is_keyring_available", return_value=False):
        assert runner.invoke(t.group, ["status"]).exit_code != 0


class TestSet:
    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_success_token(self):
        runner = click.testing.CliRunner()
        with patch("keyring.set_password") as keyring:
            rv = runner.invoke(
                t.group, ["set", "https://example.com", "token", "t0ken"]
            )

        assert rv.exit_code == 0
        keyring.assert_any_call(
            "secrets.env", '{"host": "example.com", "type": "token"}', "t0ken"
        )

    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_success_login(self):
        runner = click.testing.CliRunner()
        with (
            patch("click.prompt", return_value="P@ssw0rd"),
            patch("keyring.set_password") as keyring,
        ):
            rv = runner.invoke(t.group, ["set", "https://example.com", "demo"])

        assert rv.exit_code == 0
        keyring.assert_any_call(
            "secrets.env",
            '{"host": "example.com", "type": "login", "user": "demo"}',
            "P@ssw0rd",
        )

    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_no_password(self):
        runner = click.testing.CliRunner(mix_stderr=False)
        with patch("click.prompt", return_value=""):
            rv = runner.invoke(t.group, ["set", "https://example.com", "demo"])

        assert rv.exit_code != 0
        assert "Missing credential value." in rv.stderr

    def test_no_keyring(self):
        runner = click.testing.CliRunner()
        with patch.object(t, "is_keyring_available", return_value=False):
            rv = runner.invoke(t.group, ["set", "https://example.com", "token"])
        assert rv.exit_code != 0

    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_keyring_error(self):
        runner = click.testing.CliRunner(mix_stderr=False)
        with patch("keyring.set_password", side_effect=keyring.errors.PasswordSetError):
            rv = runner.invoke(t.group, ["set", "https://example.com", "demo", "0000"])
        assert rv.exit_code != 0
        assert "Failed to save password" in rv.stderr


class TestDel:
    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_success_token(self):
        runner = click.testing.CliRunner()
        with patch("keyring.delete_password") as keyring:
            rv = runner.invoke(t.group, ["del", "https://example.com", "token"])

        assert rv.exit_code == 0
        keyring.assert_any_call(
            "secrets.env", '{"host": "example.com", "type": "token"}'
        )

    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_success_password(self):
        runner = click.testing.CliRunner()
        with patch("keyring.delete_password") as keyring:
            rv = runner.invoke(t.group, ["del", "https://example.com", "demo"])

        assert rv.exit_code == 0
        keyring.assert_any_call(
            "secrets.env", '{"host": "example.com", "type": "login", "user": "demo"}'
        )

    def test_no_keyring(self):
        runner = click.testing.CliRunner()
        with patch.object(t, "is_keyring_available", return_value=False):
            rv = runner.invoke(t.group, ["del", "https://example.com", "token"])
        assert rv.exit_code != 0

    @pytest.mark.usefixtures("_patch_is_keyring_available")
    def test_del_error(self):
        runner = click.testing.CliRunner()
        with patch(
            "keyring.set_password", side_effect=keyring.errors.PasswordDeleteError
        ):
            rv = runner.invoke(t.group, ["del", "https://example.com", "token"])
        assert rv.exit_code == 0


def test_is_keyring_available():
    # success
    with patch("keyring.get_keyring", return_value=keyring.backends.null.Keyring()):
        assert t.is_keyring_available() is True

    # import error
    with patch.dict("sys.modules", {"keyring": None}):
        assert t.is_keyring_available() is False

    # keyring unavailable
    with patch("keyring.get_keyring", return_value=keyring.backends.fail.Keyring()):
        assert t.is_keyring_available() is False

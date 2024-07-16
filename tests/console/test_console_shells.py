import os
import signal
import subprocess
from pathlib import Path, PureWindowsPath
from unittest.mock import Mock

import pexpect
import pytest

from secrets_env.console.shells import get_shell
from secrets_env.console.shells.base import Shell
from secrets_env.console.shells.posix import (
    Bash,
    PosixShell,
    Zsh,
    prepare_activate_script,
    register_window_resize,
)
from secrets_env.console.shells.windows import WindowsShell


class TestGetShell:
    def test_default(self, monkeypatch: pytest.MonkeyPatch):
        def mock_detect_shell():
            return "sh", Path("/bin/sh")

        monkeypatch.setattr(
            "secrets_env.realms.shellingham.detect_shell", mock_detect_shell
        )

        shell = get_shell()
        assert isinstance(shell, PosixShell)


class TestShell:
    def test_activate(self):
        shell = Shell(shell_path=Path("/bin/sh"))
        with pytest.raises(NotImplementedError):
            shell.activate(environ={"key": "value"})


class TestPosixShell:
    @pytest.fixture()
    def _goto_handover_default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            PosixShell, "handover_pexpect", Mock(side_effect=ImportError)
        )
        monkeypatch.setattr("os.execv", Mock(side_effect=SystemExit()))

    @pytest.mark.usefixtures("_goto_handover_default")
    def test_warning_poetry(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.setenv("POETRY_ACTIVE", "1")

        shell = PosixShell(shell_path=Path("/bin/sh"))
        with pytest.raises(SystemExit):
            shell.handover()

        assert "Detected Poetry environment" in caplog.text

    @pytest.mark.usefixtures("_goto_handover_default")
    def test_warning_virtualenv(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ):
        monkeypatch.delenv("POETRY_ACTIVE", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", "1")

        shell = PosixShell(shell_path=Path("/bin/sh"))
        with pytest.raises(SystemExit):
            shell.handover()

        assert "Detected Python virtual environment" in caplog.text

    def test_signal_exit(self, monkeypatch: pytest.MonkeyPatch):
        mock_proc = Mock(pexpect.spawn, exitstatus=None, signalstatus=1)
        monkeypatch.setattr("pexpect.spawn", Mock(return_value=mock_proc))

        shell = PosixShell(shell_path=Path("/bin/sh"))
        assert shell.handover() == 1


class TestShellHandoverPexpect:
    @pytest.fixture(autouse=True)
    def _mock_spawn(self, monkeypatch: pytest.MonkeyPatch):
        mock_proc = Mock(pexpect.spawn, exitstatus=1)
        monkeypatch.setattr("pexpect.spawn", Mock(return_value=mock_proc))

        yield

        mock_proc.sendline.assert_called()
        mock_proc.interact.assert_called_once()

    def test_sh(self):
        shell = PosixShell(shell_path=Path("/bin/sh"))
        assert shell.handover() == 1

    def test_bash(self):
        shell = Bash(shell_path=Path("/bin/bash"))
        assert shell.handover() == 1

    def test_zsh(self):
        shell = Zsh(shell_path=Path("/bin/zsh"))
        assert shell.handover() == 1


def test_register_window_resize():
    proc = Mock(pexpect.spawn)

    register_window_resize(proc)

    os.kill(os.getpid(), signal.SIGWINCH)
    proc.setwinsize.assert_called_once()


class TestPrepareActivateScript:
    def test_script(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("TEST_CODE", "Hello World'!")
        script_path = prepare_activate_script(".sh")
        script_content = Path(script_path).read_text()
        assert "TEST_CODE='Hello World'\"'\"'!'" in script_content
        assert "export TEST_CODE" in script_content

    def test_remove_by_signal(self):
        script_path = prepare_activate_script(".sh")
        os.kill(os.getpid(), signal.SIGUSR1)
        os.kill(os.getpid(), signal.SIGUSR1)  # should not raise error
        assert not Path(script_path).exists()

    def test_remove_by_atexit(self, monkeypatch: pytest.MonkeyPatch):
        teardown_fn = None

        def mock_register(func):
            nonlocal teardown_fn
            teardown_fn = func

        monkeypatch.setattr("atexit.register", mock_register)

        # ensure teardown function is registered
        script_path = prepare_activate_script(".sh")
        assert Path(script_path).exists()
        assert teardown_fn is not None

        # invoke teardown function
        teardown_fn()
        teardown_fn()
        assert not Path(script_path).exists()


class TestWindowsShell:
    def test_handover(self, monkeypatch: pytest.MonkeyPatch):
        def mock_run(command, *, shell, text):
            assert command == "C:\\Windows\\System32\\cmd.exe"
            assert shell is True
            assert text is False
            return Mock(subprocess.CompletedProcess, returncode=7)

        monkeypatch.setattr("subprocess.run", mock_run)

        shell = WindowsShell(shell_path=PureWindowsPath(r"C:\Windows\System32\cmd.exe"))
        assert shell.handover() == 7

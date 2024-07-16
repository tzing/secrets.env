import subprocess
from pathlib import Path, PureWindowsPath
from unittest.mock import Mock

import pexpect
import pytest

from secrets_env.console.shells import get_shell
from secrets_env.console.shells.base import Shell
from secrets_env.console.shells.posix import PosixShell
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
    def test_handover_pexpect(self, monkeypatch: pytest.MonkeyPatch):
        mock_proc = Mock(pexpect.spawn, exitstatus=7)
        monkeypatch.setattr("pexpect.spawn", Mock(return_value=mock_proc))

        shell = PosixShell(shell_path=Path("/bin/sh"))
        assert shell.handover() == 7

        mock_proc.interact.assert_called_once()

    def test_handover_default(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            PosixShell, "handover_pexpect", Mock(side_effect=ImportError)
        )
        monkeypatch.setattr("os.execv", Mock(side_effect=SystemExit))

        shell = PosixShell(shell_path=Path("/bin/sh"))
        with pytest.raises(SystemExit):
            shell.handover()


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

from pathlib import Path, PureWindowsPath
from unittest.mock import Mock

import pexpect
import pytest

from secrets_env.console.shells.base import Shell


class TestShell:
    def test_activate(self):
        shell = Shell(shell_path=Path("/bin/sh"))
        with pytest.raises(NotImplementedError):
            shell.activate(environ={"key": "value"})

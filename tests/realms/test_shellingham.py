import os
from pathlib import Path
from unittest.mock import Mock

import pytest
import shellingham

from secrets_env.realms.shellingham import _detect_shell_via_shellingham, detect_shell


class TestDetectShell:
    def test_success(self):
        shell, path = detect_shell()
        assert isinstance(shell, str)
        assert isinstance(path, Path)

    @pytest.mark.skipif(
        os.getenv("CI") is None, reason="Expect GitHub Action environment"
    )
    def test_success__ci(self):
        shell, path = detect_shell()
        assert shell == "bash"
        assert path == Path("/usr/bin/bash")

    @pytest.mark.skipif(
        os.getenv("SHELL") != "/bin/zsh", reason="This is a hard-coded test for zsh"
    )
    def test_success__local(self):
        """Expect local shell is zsh"""
        shell, path = detect_shell()
        assert shell == "zsh"
        assert path == Path("/bin/zsh")

    def test_fallback(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "secrets_env.realms.shellingham._detect_shell_via_shellingham", lambda: None
        )
        monkeypatch.setenv("SHELL", "/bin/sh")
        shell, path = detect_shell()
        assert shell == "sh"
        assert path == Path("/bin/sh")


class TestDetectShellViaShellingham:
    def test_success(self):
        shell, path = detect_shell()
        assert isinstance(shell, str)
        assert isinstance(path, Path)

    def test_not_installed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("builtins.__import__", Mock(side_effect=ImportError))
        assert _detect_shell_via_shellingham() is None

    def test_error(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            "shellingham.detect_shell",
            Mock(side_effect=shellingham.ShellDetectionFailure),
        )
        assert _detect_shell_via_shellingham() is None

from __future__ import annotations

import logging
import os
import shlex
import shutil
import signal
import tempfile
import typing

from secrets_env.console.shells.base import Shell

if typing.TYPE_CHECKING:
    from pathlib import Path
    from types import FrameType
    from typing import NoReturn

    from pexpect import spawn

logger = logging.getLogger(__name__)


class PosixShell(Shell):
    def __init__(self, shell_path: Path) -> None:
        super().__init__(shell_path)
        self.script_suffix = ".sh"

    def handover(self) -> int | None:
        try:
            return self.handover_pexpect()
        except ImportError:
            return self.handover_default()

    def handover_default(self) -> NoReturn:
        logger.debug("Handover current process to %s", self.shell_path)
        os.execv(self.shell_path, ["-i"])

    def handover_pexpect(self) -> int | None:
        import pexpect

        logger.debug("Spawn shell %s with pexpect", self.shell_path)

        # spawn the shell
        dims = shutil.get_terminal_size()
        proc = pexpect.spawn(
            str(self.shell_path), ["-i"], dimensions=(dims.lines, dims.columns)
        )

        # post spawn actions
        self.do_post_spawn(proc)

        # give control to user
        NO_ESCAPE = typing.cast(str, None)
        proc.interact(escape_character=NO_ESCAPE)
        proc.close()

        if proc.exitstatus is not None:
            # don't know why pyright interprets `exitstatus` as bool
            return typing.cast(int, proc.exitstatus)
        return proc.signalstatus

    def do_post_spawn(self, proc: spawn) -> None:
        # register signal handler for window resize
        register_window_resize(proc)

        # prepare activation script
        script_path = create_temporary_script(self.script_suffix)

        with open(script_path, "w") as fd:
            # transfer current environment
            for key, value in os.environ.items():
                print(f"{key}='{value}'", file=fd)
                print(f"export {key}", file=fd)

            # ask the shell to send us a signal when it finishes
            print(f"kill -USR1 {os.getpid()}", file=fd)

        # source the script
        self._source_script(proc, script_path)

    def _source_script(self, proc: spawn, script_path: str) -> None:
        proc.sendline(f". {shlex.quote(script_path)}")


def register_window_resize(proc: spawn) -> None:
    """
    Register a signal handler to resize the window of the spawned shell.
    """

    def sigwinch_handler(sig: int, data: FrameType | None):  # pragma: no cover
        nonlocal proc
        dims = shutil.get_terminal_size()
        proc.setwinsize(dims.lines, dims.columns)

    signal.signal(signal.SIGWINCH, sigwinch_handler)


def create_temporary_script(suffix: str) -> str:
    """
    Create a temporary file and delete it when receiving SIGUSR1.
    """
    fd, filename = tempfile.mkstemp(prefix="secrets-env-", suffix=suffix)
    os.close(fd)

    logger.debug("Created temporary script %s", filename)

    def sigusr1_handler(sig: int, data: FrameType | None):
        nonlocal filename
        logger.debug("Received SIGUSR1, removing %s", filename)
        try:
            os.remove(filename)
        except FileNotFoundError:
            ...

    signal.signal(signal.SIGUSR1, sigusr1_handler)

    return filename

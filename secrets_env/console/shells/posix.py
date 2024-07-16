from __future__ import annotations

import atexit
import logging
import os
import shlex
import shutil
import signal
import tempfile
import typing
from pathlib import Path

from pexpect import spawn

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
        self.shell_args = ["-i"]
        self.script_suffix = ".sh"

    def handover(self) -> int | None:
        try:
            return self.handover_pexpect()
        except ImportError:
            return self.handover_default()

    def handover_default(self) -> NoReturn:
        logger.debug("Handover current process to %s", self.shell_path)

        if os.getenv("POETRY_ACTIVE"):
            logger.warning(
                "Detected Poetry environment. "
                "Some variables may be overwritten in the nested environment."
            )
            logger.warning("Please consider using secrets.env as a Poetry plugin.")

        elif os.getenv("VIRTUAL_ENV"):
            logger.warning(
                "Detected Python virtual environment. "
                "Some variables may be overwritten in the nested environment."
            )
            logger.warning(
                "Please consider deactivating the virtual environment first."
            )

        os.execv(self.shell_path, self.shell_args)

    def handover_pexpect(self) -> int | None:
        import pexpect

        logger.debug("Spawn shell %s with pexpect", self.shell_path)

        # spawn the shell
        dims = shutil.get_terminal_size()
        proc = pexpect.spawn(
            str(self.shell_path), self.shell_args, dimensions=(dims.lines, dims.columns)
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

        # setup shell by sourcing the activate script
        script_path = prepare_activate_script(self.script_suffix)
        self._source_script(proc, script_path)

    def _source_script(self, proc: spawn, script_path: str) -> None:
        proc.sendline(f". {shlex.quote(script_path)}")


class Bash(PosixShell):
    def __init__(self, shell_path: Path) -> None:
        super().__init__(shell_path)
        self.script_suffix = ".bash"


class Zsh(Bash):
    def __init__(self, shell_path: Path) -> None:
        super().__init__(shell_path)
        self.script_suffix = ".zsh"

    def do_post_spawn(self, proc: spawn) -> None:
        proc.setecho(False)
        super().do_post_spawn(proc)

    def _source_script(self, proc: spawn, script_path: str) -> None:
        source_command = f". {shlex.quote(script_path)}"
        proc.sendline(f"emulate bash -c {shlex.quote(source_command)}")


def register_window_resize(proc: spawn) -> None:
    """
    Register a signal handler to resize the window of the spawned shell.
    """

    def sigwinch_handler(sig: int, data: FrameType | None):
        nonlocal proc
        dims = shutil.get_terminal_size()
        proc.setwinsize(dims.lines, dims.columns)

    signal.signal(signal.SIGWINCH, sigwinch_handler)


def prepare_activate_script(suffix: str) -> str:
    """
    Prepare a temporary script that activates the virtual environment.
    """
    # create a temporary script
    fid, script_path = tempfile.mkstemp(prefix="secrets-env-", suffix=suffix)
    logger.debug("Created temporary script %s", script_path)

    # registers a SIGUSR1 handler to delete the script
    def sigusr1_handler(sig: int, data: FrameType | None):
        nonlocal script_path
        logger.debug("Received SIGUSR1, removing %s", script_path)
        try:
            os.remove(script_path)
        except FileNotFoundError:
            ...

    signal.signal(signal.SIGUSR1, sigusr1_handler)

    # remove the script upon exit if not removed
    def remove_script():
        nonlocal script_path
        try:
            os.remove(script_path)
        except FileNotFoundError:
            ...

    atexit.register(remove_script)

    # write the script
    with os.fdopen(fid, "w") as fd:
        # transfer current environment
        for key, value in os.environ.items():
            print(f"{key}={shlex.quote(value)}", file=fd)
            print(f"export {key}", file=fd)

        # request the shell to notify us via USR1 signal upon completion
        print(f"kill -USR1 {os.getpid()}", file=fd)

    return script_path

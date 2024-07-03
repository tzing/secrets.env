from __future__ import annotations

import logging
import os
import shutil
import signal
import typing

from secrets_env.console.shells.base import Shell

if typing.TYPE_CHECKING:
    from types import FrameType
    from typing import NoReturn

logger = logging.getLogger(__name__)


class PosixShell(Shell):
    def handover(self) -> int | None:
        try:
            return self.handover_pexpect()
        except ImportError:
            return self.handover_fallback()

    def handover_pexpect(self) -> int | None:
        import pexpect

        logger.debug("Spawn shell %s with pexpect", self.shell_path)

        # spawn the shell
        dims = shutil.get_terminal_size()
        proc = pexpect.spawn(
            str(self.shell_path), ["-i"], dimensions=(dims.lines, dims.columns)
        )

        # post spawn actions
        def sigwinch_handler(sig: int, data: FrameType | None):  # pragma: no cover
            # handle window resize
            nonlocal proc
            dims = shutil.get_terminal_size()
            proc.setwinsize(dims.lines, dims.columns)

        signal.signal(signal.SIGWINCH, sigwinch_handler)

        # give control to user
        NO_ESCAPE = typing.cast(str, None)
        proc.interact(escape_character=NO_ESCAPE)
        proc.close()

        if proc.exitstatus is None:
            return proc.signalstatus
        # don't know why pexpect mark exit status as bool
        return typing.cast(int, proc.exitstatus)

    def handover_fallback(self) -> NoReturn:
        logger.debug("Handover current process to %s", self.shell_path)
        os.execv(self.shell_path, ["-i"])

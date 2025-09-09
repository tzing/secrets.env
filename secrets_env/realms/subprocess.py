from __future__ import annotations

import logging
import re
import shlex
import subprocess
import typing

if typing.TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import Literal

logger = logging.getLogger(__name__)
regex_ansi = re.compile(r"\033\[[;?0-9]*[a-zA-Z]")


class SubprocessLoggerAdapter:
    """Logger adapter for subprocess output."""

    def __init__(self, logger: logging.Logger, channel: Literal["stdout", "stderr"]):
        self.logger = logger
        self.channel = channel

    def log(self, level: int, msg) -> None:
        if not self.logger.isEnabledFor(level):
            return

        msg = strip_ansi(str(msg).rstrip())
        for line in msg.splitlines():
            self.logger.log(level, f"[{self.channel}]> {line}")

    def debug(self, msg) -> None:
        self.log(logging.DEBUG, msg)

    def error(self, msg) -> None:
        self.log(logging.ERROR, msg)


stdout_logger = SubprocessLoggerAdapter(logger, "stdout")
stderr_logger = SubprocessLoggerAdapter(logger, "stderr")


def check_output(
    commands: Sequence[str],
    *,
    level_output: int | None = logging.DEBUG,
    level_error: int | None = logging.ERROR,
) -> str:
    """
    Run a command and return the output.

    Parameters
    ----------
    commands : list[str]
        A list of commands to run.
    level_output : int, optional
        The logging level to use for the output, by default :py:data:`logging.DEBUG`.
        Set to :py:obj:`None` to disable logging the output.
    level_error : int, optional
        The logging level to use for the error, by default :py:data:`logging.ERROR`.
        Set to :py:obj:`None` to disable logging the error.

    Returns
    -------
    str
        The output of the command.

    Raises
    ------
    subprocess.CalledProcessError
        If the command exits with a non-zero status.
    """

    def _quote(s) -> str:
        return shlex.quote(strip_ansi(str(s)))

    logger.debug("$ %s", " ".join(map(_quote, commands)))

    try:
        proc = subprocess.run(
            args=commands,
            capture_output=True,
            check=True,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError as e:
        logger.debug("> return code: %d", e.returncode)
        stdout_logger.log(level_error or 0, e.stdout or "")
        stderr_logger.log(level_error or 0, e.stderr or "")
        raise

    logger.debug("> return code: %d", proc.returncode)
    stdout_logger.log(level_output or 0, proc.stdout)
    stderr_logger.log(level_output or 0, proc.stderr)
    return proc.stdout


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return regex_ansi.sub("", value)

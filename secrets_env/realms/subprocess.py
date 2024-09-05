from __future__ import annotations

import logging
import re
import shlex
import subprocess
import typing

if typing.TYPE_CHECKING:
    from typing import Literal, Sequence

logger = logging.getLogger(__name__)
regex_ansi = re.compile(r"\033\[[;?0-9]*[a-zA-Z]")


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
        logger.debug("< return code: %d", e.returncode)
        write_output("stdout", e.stdout, level_error)
        write_output("stderr", e.stderr, level_error)
        raise

    logger.debug("< return code: %d", proc.returncode)
    write_output("stdout", proc.stdout, level_output)
    write_output("stderr", proc.stderr, level_output)
    return proc.stdout


def write_output(
    channel: Literal["stdout", "stderr"],
    message: str,
    level: int | None = logging.DEBUG,
):
    """
    Write the output to the log.

    Parameters
    ----------
    channel : str
        The channel name for the output. Used as the prefix in the log message.
    message : str
        The output message.
    level : int, optional
        The logging level to use for the output, by default :py:data:`logging.DEBUG`.
        Set to :py:obj:`None` to disable logging the output.
    """
    if level is None:
        return
    message = message or ""
    message = strip_ansi(message.rstrip())
    for line in message.splitlines():
        logger.log(level, f"<[{channel}] {line}")


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return regex_ansi.sub("", value)

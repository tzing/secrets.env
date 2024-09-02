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


def check_output(commands: Sequence[str], *, write_output: bool = True) -> str:
    """
    A wrapper around :py:func:`subprocess.check_output` that logs the command
    and output, and returns the output as a string.

    Parameters
    ----------
    commands : list[str]
        A list of commands to run.
    write_output : bool, optional
        Whether to write the output to the log, by default True.

    Returns
    -------
    str
        The output of the command.
    """

    def _quote(s) -> str:
        return shlex.quote(strip_ansi(str(s)))

    logger.debug("$ %s", " ".join(map(_quote, commands)))

    try:
        stdout = subprocess.check_output(
            commands, stderr=subprocess.PIPE, encoding="utf-8"
        )
    except subprocess.CalledProcessError as e:
        logging.debug("< return code: %d", e.returncode)
        log_output("stderr", e.stderr)
        raise

    if write_output:
        log_output("stdout", stdout)

    return stdout


def log_output(
    channel: Literal["stdout", "stderr"], message: str, level: int = logging.DEBUG
):
    """Write the output to the log."""
    message = strip_ansi(message.rstrip())
    for line in message.splitlines():
        logger.log(level, f"<[{channel}] {line}")


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return regex_ansi.sub("", value)

from __future__ import annotations

import logging
import re
import shlex
import subprocess
import typing

if typing.TYPE_CHECKING:
    from typing import Sequence

logger = logging.getLogger(__name__)
regex_ansi = re.compile(r"\033\[[;?0-9]*[a-zA-Z]")


def log_output(channel: str, message: str, level: int = logging.DEBUG):
    """Write the output to the log."""
    message = strip_ansi(message.rstrip())
    for line in message.splitlines():
        logger.log(level, f"<[{channel}] {line}")


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return regex_ansi.sub("", value)

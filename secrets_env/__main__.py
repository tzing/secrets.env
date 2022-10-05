import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import click
import click_option_group

import secrets_env

logger = logging.getLogger(__name__)


class Handler(logging.Handler):
    """Send the logs to click's echo.

    This app has more than one entry point: command line tool and poetry plugin,
    which use different frameworks. This app reports the information using the
    built-in 'logging' module. Then use this customized handler for converting
    them to the format in corresponding framework, powered with their features
    like color stripping on non-interactive terminal."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return
        click.echo(msg, file=sys.stderr)


class Formatter(logging.Formatter):
    """Add colors based on internal expression. It doesn't use click's 'style'
    function because the nested style breaks it."""

    C_RED = "\033[31m"
    C_YELLOW = "\033[33m"
    C_CYAN = "\033[36m"
    C_WHITE = "\033[37m"

    S_BRIGHT = "\033[1m"
    S_DIM = "\033[2m"
    S_RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        if record.levelno == logging.DEBUG:
            msg = f"[{secrets_env.__name__}] {msg}"

        # color msg by log level
        base_color = ""
        if record.levelno >= logging.ERROR:
            base_color = self.C_RED + self.S_BRIGHT
        elif record.levelno == logging.WARNING:
            base_color = self.C_YELLOW + self.S_BRIGHT
        elif record.levelno == logging.DEBUG:
            base_color = self.C_WHITE + self.S_DIM

        if base_color:
            msg = base_color + msg + self.S_RESET

        # tag translate
        reset_code = base_color or self.S_RESET

        msg = msg.replace("<mark>", self.C_CYAN)
        msg = msg.replace("</mark>", reset_code)
        msg = msg.replace("<data>", self.S_RESET + self.C_YELLOW)
        msg = msg.replace("</data>", reset_code)

        return msg


if __name__ == "__main__":
    entrypoint()

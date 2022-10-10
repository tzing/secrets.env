import enum
import functools
import logging
import sys
from typing import Callable

import click

logger = logging.getLogger(__name__)


class Verbosity(enum.IntEnum):
    def __new__(
        cls, value: int, levelno_internal: int, levelno_others: int
    ) -> "Verbosity":
        obj = int.__new__(cls)
        obj._value_ = value
        obj.levelno_internal = levelno_internal
        obj.levelno_others = levelno_others
        return obj

    Quiet = -1, logging.WARNING, logging.WARNING
    """Only show errors."""

    Default = 0, logging.INFO, logging.WARNING
    """Show INFO for secrets.env messages. Show WARNING for others."""

    Verbose = 1, logging.NOTSET, logging.WARNING
    """Show all for secrets.env messages. Show WARNING for others."""

    Debug = 3, logging.NOTSET, logging.NOTSET
    """Show everything."""


class SecretsEnvHandler(logging.Handler):
    """Send the logs to click's echo.

    This app has more than one entry point: command line tool and poetry plugin,
    which use different frameworks. This app reports the information using the
    built-in 'logging' module. Then use this customized handler for converting
    them to the format in corresponding framework, powered with their features
    like color stripping on non-interactive terminal."""

    def __init__(self, verbosity: Verbosity) -> None:
        super().__init__(logging.NOTSET)
        self.verbosity = verbosity

    def filter(self, record: logging.LogRecord) -> bool:
        is_internal_log = record.name.startswith("secrets_env.")
        is_internal_log |= record.name == "secrets_env"

        if is_internal_log:
            return record.levelno >= self.verbosity.levelno_internal
        else:
            return record.levelno >= self.verbosity.levelno_others

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return
        click.echo(msg, file=sys.stderr)


class SecretsEnvFormatter(logging.Formatter):
    """Add colors based on internal expression. It doesn't use click's 'style'
    function because the nested style breaks it."""

    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_CYAN = "\033[36m"
    C_WHITE = "\033[37m"
    C_RESET = "\033[39m"

    S_BRIGHT = "\033[1m"
    S_DIM = "\033[2m"
    S_RESET = "\033[0m"

    def __init__(self, tag_highlight: bool) -> None:
        super().__init__(
            fmt=None, datefmt=None, style="%", validate=True, defaults=None
        )
        self.tag_highlight = tag_highlight

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        # color msg by log level
        base_style = base_color = ""
        if record.levelno >= logging.ERROR:
            base_color = self.C_RED
            base_style = self.S_BRIGHT
        elif record.levelno == logging.WARNING:
            base_color = self.C_YELLOW
            base_style = self.S_BRIGHT
        elif record.levelno == logging.DEBUG:
            base_color = self.C_WHITE
            base_style = self.S_DIM

        if base_color:
            msg = base_style + base_color + msg + self.S_RESET

        # prefix
        name, *_ = record.name.split(".", 1)  # always use package name
        msg = f"[{name}] {msg}"

        # tag translate
        if self.tag_highlight:
            reset_code = base_color or self.C_RESET

            msg = msg.replace("<mark>", self.C_CYAN)
            msg = msg.replace("</mark>", reset_code)
            msg = msg.replace("<data>", self.C_GREEN)
            msg = msg.replace("</data>", reset_code)

        return msg

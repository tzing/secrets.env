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

    Verbose = 1, logging.DEBUG, logging.WARNING
    """Show all for secrets.env messages. Show WARNING for others."""

    Debug = 2, logging.DEBUG, logging.DEBUG
    """Show everything."""


class ClickHandler(logging.Handler):
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
        super().__init__()
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
            msg = msg.replace("<error>", self.C_RED)
            msg = msg.replace("</error>", reset_code)

        return msg


def add_output_options(func: Callable[..., None]) -> Callable[..., None]:
    # add options
    click.option(
        "-v",
        "--verbose",
        count=True,
        help="Increase output verbosity.",
    )(func)
    click.option(
        "-q",
        "--quiet",
        is_flag=True,
        help="Silent mode. Don't show output until error.",
    )(func)

    # wrap original function for post-parsing actions
    @functools.wraps(func)
    def decorated(verbose: int, quiet: bool, *args, **kwargs):
        if verbose and quiet:
            click.secho(
                "Option --verbose and --quiet are mutually exclusive.",
                err=True,
                fg="red",
            )
            raise click.Abort()

        setup_logging(verbose, quiet)

        return func(*args, **kwargs)

    return decorated


def setup_logging(verbose: int, quiet: bool):
    """Setup logging module and forwards internal messages to click."""
    if quiet:
        verbosity = Verbosity.Quiet
    else:
        # the customized verbosity expression must in [-1, 2]
        verbose = min(verbose, 2)
        verbosity = Verbosity(verbose)

    # logging for internal messages
    internal_handler = ClickHandler()
    internal_handler.setFormatter(SecretsEnvFormatter(True))

    internal_logger = logging.getLogger("secrets_env")
    internal_logger.setLevel(verbosity.levelno_internal)
    internal_logger.addHandler(internal_handler)
    internal_logger.propagate = False

    # logging for external modules
    root_handler = ClickHandler()
    root_handler.setFormatter(SecretsEnvFormatter(False))

    logging.root.setLevel(verbosity.levelno_others)
    logging.root.addHandler(root_handler)

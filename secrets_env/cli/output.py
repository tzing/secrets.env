import enum
import functools
import logging
import sys
from typing import Callable, Optional

import click

from secrets_env.utils import removeprefix

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

    def __init__(self, extra_filter_level: Optional[int] = None) -> None:
        """
        Parameters
        ----------
        extra_filter_level : int | None
            Log level to apply in the *extra filter feature*. Set to None to
            keep the behavior like normal handler.

        Note
        ----
        Extra filter feature is designed for secrets.env itself. In this app we
        want to let some special message penetrates the filters. So we'll set
        this handler into DEBUG level, receiving all the message and do the log
        level filtering inside.
        """
        super().__init__(logging.NOTSET)
        self.extra_filter_level = extra_filter_level

    def filter(self, record: logging.LogRecord):
        """To let <!important> tag penetrate the level-based filters."""
        if self.extra_filter_level is not None:
            # accept <!important> to penetrate filter
            if record.msg.startswith("<!important>"):
                return True

            # level based filter
            if record.levelno < self.extra_filter_level:
                return False

        # fallback to normal filtering rules
        return super().filter(record)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return
        click.echo(msg, file=sys.stderr)


class ColorFormatter(logging.Formatter):
    """Add colors based on log level."""

    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_CYAN = "\033[36m"
    C_WHITE = "\033[37m"
    C_RESET = "\033[39m"

    S_BRIGHT = "\033[1m"
    S_DIM = "\033[2m"
    S_RESET = "\033[0m"

    def get_color(self, level: int):
        if level >= logging.ERROR:
            return self.C_RED
        elif level >= logging.WARNING:
            return self.C_YELLOW
        elif level <= logging.DEBUG:
            return self.C_WHITE
        return ""

    def get_style(self, level: int):
        if level >= logging.WARNING:
            return self.S_BRIGHT
        elif level <= logging.DEBUG:
            return self.S_DIM
        return ""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        # add color and style
        color = self.get_color(record.levelno)
        style = self.get_style(record.levelno)

        if color or style:
            msg = f"{style}{color}{msg}{self.S_RESET}"

        # add package name as prefix
        logger_name, *_ = record.name.split(".", 1)
        msg = f"[{logger_name}] {msg}"

        return msg


class SecretsEnvFormatter(ColorFormatter):
    """Add colors for internal expression."""

    def format(self, record: logging.LogRecord) -> str:
        # remvoe the <!important> prefix, which was used for filter
        record.msg = removeprefix(record.msg, "<!important>")
        msg = super().format(record)

        # add color based on internal expressions
        reset_code = self.get_color(record.levelno) or self.C_RESET

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
    internal_handler = ClickHandler(verbosity.levelno_internal)
    internal_handler.setFormatter(SecretsEnvFormatter())

    internal_logger = logging.getLogger("secrets_env")
    internal_logger.addHandler(internal_handler)
    internal_logger.setLevel(logging.DEBUG)
    internal_logger.propagate = False

    # logging for external modules
    root_handler = ClickHandler()
    root_handler.setFormatter(ColorFormatter())

    logging.root.setLevel(verbosity.levelno_others)
    logging.root.addHandler(root_handler)

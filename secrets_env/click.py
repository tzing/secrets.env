import functools
import logging
import sys
from typing import Callable, Optional

import click

VERBOSITY = {
    # verbosity: (level for secrets.env logs, level for other logs)
    # Quiet: only show errors.
    -1: (logging.WARNING, logging.WARNING),
    # Default: show INFO for secrets.env messages. show WARNING for others.
    0: (logging.INFO, logging.WARNING),
    # Verbose: show all for secrets.env messages. show WARNING for others.
    1: (logging.DEBUG, logging.WARNING),
    # Debug: show everything.
    2: (logging.DEBUG, logging.DEBUG),
}


class ClickHandler(logging.Handler):
    """Send the logs to :py:func:`click.echo`.

    This app has more than one entry point: command line tool and poetry plugin,
    which use different frameworks. This app reports the information using the
    built-in :py:mod:`logging` module. Then use this customized handler for
    converting them to the format in corresponding framework, powered with their
    features like color stripping on non-interactive terminal."""

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
        """Overrides :py:meth:`logging.Handler.filter` rules to make ``<!important>``
        tag penetrate all the filters."""
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

    SGR_FORE_RED = "\033[31m"
    SGR_FORE_GREEN = "\033[32m"
    SGR_FORE_YELLOW = "\033[33m"
    SGR_FORE_CYAN = "\033[36m"
    SGR_FORE_WHITE = "\033[37m"
    SGR_FORE_RESET = "\033[39m"

    SGR_BRIGHT = "\033[1m"
    SGR_DIM = "\033[2m"
    SGR_UNDERLINE = "\033[4m"
    SGR_UNDERLINE_RESET = "\033[24m"
    SGR_RESET_ALL = "\033[0m"

    def get_color(self, level: int):
        if level >= logging.ERROR:
            return self.SGR_FORE_RED
        elif level >= logging.WARNING:
            return self.SGR_FORE_YELLOW
        elif level <= logging.DEBUG:
            return self.SGR_FORE_WHITE
        return ""

    def get_style(self, level: int):
        if level >= logging.WARNING:
            return self.SGR_BRIGHT
        elif level <= logging.DEBUG:
            return self.SGR_DIM
        return ""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        # add color and style
        color = self.get_color(record.levelno)
        style = self.get_style(record.levelno)

        if color or style:
            msg = f"{style}{color}{msg}{self.SGR_RESET_ALL}"

        # add package name as prefix
        logger_name, *_ = record.name.split(".", 1)
        msg = f"[{logger_name}] {msg}"

        return msg


class SecretsEnvFormatter(ColorFormatter):
    """Add colors for internal expression."""

    def format(self, record: logging.LogRecord) -> str:
        from secrets_env.utils import removeprefix

        # remvoe the <!important> prefix, which was used for filter
        record.msg = removeprefix(record.msg, "<!important>")
        msg = super().format(record)

        # add color based on internal expressions
        reset_code = self.get_color(record.levelno) or self.SGR_FORE_RESET

        msg = msg.replace("<mark>", self.SGR_FORE_CYAN)
        msg = msg.replace("</mark>", reset_code)

        msg = msg.replace("<data>", self.SGR_FORE_GREEN)
        msg = msg.replace("</data>", reset_code)

        msg = msg.replace("<error>", self.SGR_FORE_RED)
        msg = msg.replace("</error>", reset_code)

        msg = msg.replace("<link>", self.SGR_UNDERLINE)
        msg = msg.replace("</link>", self.SGR_UNDERLINE_RESET)

        return msg


def add_output_options(func: Callable[..., None]) -> Callable[..., None]:
    """Add -v/-q options to the click command, and call :py:func:`setup_logging`
    before the command executed."""
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
        help="Silent mode. Don't show logs until error.",
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


def setup_logging(verbose: int = 0, quiet: bool = False):
    """Setup :py:mod:`logging` and forwards messages to :py:mod:`click`."""
    if quiet:
        verbose = -1
    else:
        verbose = min(verbose, 2)

    levelno_internal, levelno_others = VERBOSITY[verbose]

    # logging for internal messages
    internal_handler = ClickHandler(levelno_internal)
    internal_handler.setFormatter(SecretsEnvFormatter())

    internal_logger = logging.getLogger("secrets_env")
    internal_logger.addHandler(internal_handler)
    internal_logger.setLevel(logging.DEBUG)
    internal_logger.propagate = False

    # logging for external modules
    root_handler = ClickHandler()
    root_handler.setFormatter(ColorFormatter())

    logging.root.setLevel(levelno_others)
    logging.root.addHandler(root_handler)


@click.group(
    context_settings={
        "help_option_names": ["-h", "--help"],
    }
)
def entrypoint():
    """Secrets.env is a tool that could put secrets from vault to environment
    variables."""

from __future__ import annotations

import logging
import sys

import click


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
        if level >= logging.ERROR:
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
        # remvoe the <!important> prefix, which was used for filter
        record.msg = record.msg.removeprefix("<!important>")
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


class LevelFilter(logging.Filter):
    """Filter logs based on log level."""

    def __init__(self, level: int):
        super().__init__()
        self.level = level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.level


class SecretsEnvFilter(LevelFilter):
    """Filter logs based on log level but allow <!important> tag to penetrate."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg.startswith("<!important>"):
            return True
        return super().filter(record)


class ClickHandler(logging.Handler):
    """
    Send the logs to :py:func:`click.echo`.

    This app has more than one entry point: command line tool and poetry plugin,
    which use different frameworks. This app reports the information using the
    built-in :py:mod:`logging` module. Then use this customized handler for
    converting them to the format in corresponding framework, powered with their
    features like color stripping on non-interactive terminal.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return
        click.echo(msg, file=sys.stderr)

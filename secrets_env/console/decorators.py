from __future__ import annotations

import enum
import functools
import logging
import typing

import click

import secrets_env.utils
from secrets_env.console.loggings import (
    ClickHandler,
    ColorFormatter,
    SecretsEnvFilter,
    SecretsEnvFormatter,
)

if typing.TYPE_CHECKING:
    from typing import Callable, Self


class Verbosity(enum.IntEnum):
    level_self: int
    """Logging level for secrets.env messages."""

    level_dependency: int
    """Logging level for messages from other modules."""

    def __new__(cls, value: int, level_self: int, level_dependency: int) -> Self:
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.level_self = level_self
        obj.level_dependency = level_dependency
        return obj

    Quiet = -1, logging.WARNING, logging.WARNING
    """Quiet mode. Only show warnings and errors."""

    Default = 0, logging.INFO, logging.WARNING
    """Default mode. Show info for secrets.env messages. Show warning for others."""

    Verbose = 1, logging.DEBUG, logging.WARNING
    """Verbose mode. Show all for secrets.env messages. Show warning for others."""

    Debug = 2, logging.DEBUG, logging.DEBUG
    """Debug mode. Show everything."""


def with_output_options(func: Callable[..., None]) -> Callable[..., None]:
    """
    Decorator to add verbosity options to the click command and automatically
    setup logging before the command executed.
    """
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
                "Option `-v` / `--verbose` and `-q` / `--quiet` are mutually exclusive.",
                err=True,
                fg="red",
            )
            raise click.Abort()

        verbose = min(verbose, 2)
        if quiet:
            verbose = -1
        _setup_logging(Verbosity(verbose))

        return func(*args, **kwargs)

    return decorated


def _setup_logging(verbosity: Verbosity):
    # setup handler for output messages from secrets.env
    self_handler = ClickHandler()
    self_handler.setFormatter(SecretsEnvFormatter())
    self_handler.addFilter(SecretsEnvFilter(verbosity.level_self))

    self_logger = logging.getLogger("secrets_env")
    self_logger.addHandler(self_handler)
    self_logger.setLevel(logging.DEBUG)
    self_logger.propagate = False

    # setup handler for output messages from other modules
    dependency_handler = ClickHandler()
    dependency_handler.setFormatter(ColorFormatter())

    logging.root.setLevel(verbosity.level_dependency)
    logging.root.addHandler(dependency_handler)

    # capture warnings
    secrets_env.utils.setup_capture_warnings()

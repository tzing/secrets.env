"""Adapt poetry's plugin framework to automatically load secrets on specific
poetry commands.
"""

from __future__ import annotations

import logging
import os
import typing

from cleo.events.console_command_event import ConsoleCommandEvent
from cleo.events.console_events import COMMAND
from cleo.formatters.style import Style
from cleo.io.outputs.output import Verbosity
from poetry.plugins.application_plugin import ApplicationPlugin

import secrets_env

if typing.TYPE_CHECKING:
    from typing import ClassVar

    from cleo.events.event import Event
    from cleo.events.event_dispatcher import EventDispatcher
    from cleo.io.outputs.output import Output
    from poetry.console.application import Application

logger = logging.getLogger(__name__)


class SecretsEnvPlugin(ApplicationPlugin):
    def activate(self, application: Application) -> None:
        if application.event_dispatcher:
            application.event_dispatcher.add_listener(COMMAND, self.load_secret)

    def load_secret(
        self,
        event: Event,
        event_name: str,
        dispatcher: EventDispatcher,
    ) -> None:
        assert isinstance(event, ConsoleCommandEvent)  # satisfy type check
        if event.command.name not in ("run", "shell"):
            return

        self.setup_output(event.io.output)
        logger.debug("Start secrets.env poetry plugin.")

        secrets = secrets_env.read_values()
        if not secrets:
            return

        for name, value in secrets.items():
            os.environ[name] = value

    def setup_output(self, output: Output) -> None:
        """Forwards internal messages to :py:mod:`cleo`.

        Secrets.env writes all messages using :py:mod:`logging`. But cleo hides
        all the logs by default, including warning and error messages.

        This method forwards all internal logs from secrets.env to cleo. (Re)assign
        the verbosity level in the customized Handler and colored the output using
        the custom format, powered with cleo's formatter."""
        # set output format
        output.formatter.set_style("debug", Style("light_gray", options=["dark"]))
        output.formatter.set_style("warning", Style("yellow", options=["bold"]))
        output.formatter.set_style("link", Style(options=["underline"]))

        # send internal message to cleo
        # see docstring in Handler for details
        handler = CleoHandler(output)
        handler.setFormatter(CleoFormatter())

        root_logger = logging.getLogger("secrets_env")
        root_logger.setLevel(logging.DEBUG)
        root_logger.propagate = False
        root_logger.addHandler(handler)


class CleoHandler(logging.Handler):
    """Send the logs to cleo's IO module.

    This app has more than one entry point: command line tool and poetry plugin,
    which use different frameworks. This app reports the information using the
    built-in 'logging' module. Then use this customized handler for converting
    them to the format in corresponding framework, powered with their features
    like color stripping on non-interactive terminal."""

    VERBOSITY: ClassVar = {
        logging.DEBUG: Verbosity.VERY_VERBOSE,
        logging.INFO: Verbosity.VERBOSE,
        logging.WARNING: Verbosity.NORMAL,
        logging.ERROR: Verbosity.QUIET,
        logging.CRITICAL: Verbosity.QUIET,
    }

    def __init__(self, output: Output) -> None:
        super().__init__(logging.NOTSET)
        self.output = output

    def emit(self, record: logging.LogRecord) -> None:
        if record.msg.startswith("<!important>"):
            verbosity = Verbosity.QUIET
        else:
            verbosity = self.VERBOSITY.get(record.levelno, Verbosity.NORMAL)

        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return

        self.output.write_line(msg, verbosity=verbosity)


class CleoFormatter(logging.Formatter):
    """Translates internal expression into cleo's format."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        msg = msg.removeprefix("<!important>")

        # tag translate
        # uses builtin tags for aligning the appearance with poetry and other plugins
        msg = msg.replace("<mark>", "<info>").replace("</mark>", "</info>")
        msg = msg.replace("<data>", "<comment>").replace("</data>", "</comment>")

        # add color
        if record.levelno == logging.ERROR:
            msg = f"<error>{msg}</error>"
        elif record.levelno == logging.WARNING:
            msg = f"<warning>{msg}</warning>"
        elif record.levelno == logging.DEBUG:
            msg = f"[{secrets_env.__name__}] <debug>{msg}</debug>"

        return msg

import logging
import os
import typing

from cleo.events.console_events import COMMAND
from cleo.formatters.style import Style
from cleo.io.outputs.output import Verbosity
from poetry.console.commands.run import RunCommand
from poetry.console.commands.shell import ShellCommand
from poetry.plugins.application_plugin import ApplicationPlugin

import secrets_env

if typing.TYPE_CHECKING:
    from cleo.events.console_command_event import ConsoleCommandEvent
    from cleo.events.event_dispatcher import EventDispatcher
    from cleo.io.outputs.output import Output
    from poetry.console.application import Application

logger = logging.getLogger(__name__)


class SecretsEnvPlugin(ApplicationPlugin):
    def activate(self, application: "Application") -> None:
        application.event_dispatcher.add_listener(COMMAND, self.load_secret)

    def load_secret(
        self,
        event: "ConsoleCommandEvent",
        event_name: str,
        dispatcher: "EventDispatcher",
    ) -> None:
        if not isinstance(event.command, (RunCommand, ShellCommand)):
            return

        self.setup_output(event.io.output)
        logger.debug("Start secrets.env poetry plugin.")

        config = secrets_env.load_config()
        if not config:
            # skip logging. already show error in `load_config`
            return

        reader = secrets_env.KVReader(config.url, config.auth)
        secrets = reader.get_values(config.secret_specs.values())

        cnt_loaded = 0
        for name, spec in config.secret_specs.items():
            value = secrets.get(spec)
            if not value:
                # skip logging. already show warning in `get_value`
                continue

            logger.debug("Load <info>%s</info>", name)
            os.environ[name] = value
            cnt_loaded += 1

        if cnt_loaded == len(config.secret_specs):
            logger.info("<info>%d</info> secrets loaded", len(secrets))
        else:
            logger.warning(
                "<error>%d</error> / %d secrets loaded",
                cnt_loaded,
                len(config.secret_specs),
            )

    def setup_output(self, output: "Output") -> None:
        """Forwards internal messages to cleo.

        Secrets.env internally uses logging module for showing messages to users.
        But cleo hides the logs, unless `-vv` (VERY_VERBOSE) is set, this made
        it harder to show warnings or errors.

        So it forwards all internal logs from secrets.env to cleo. (Re)assign the
        verbosity level in the Handler and colored the output using the custom
        Formatter, powered with cleo's formatter."""
        # set output format
        output.formatter.set_style("debug", Style("white"))
        output.formatter.set_style("warning", Style("yellow"))

        # send internal message to cleo
        # see docstring in Handler for details
        handler = Handler(output)
        handler.setFormatter(Formatter())

        root_logger = logging.getLogger("secrets_env")
        root_logger.setLevel(logging.DEBUG)
        root_logger.propagate = False
        root_logger.addHandler(handler)


class Handler(logging.Handler):
    """Send the logs to cleo's IO module."""

    VERBOSITY = {
        logging.DEBUG: Verbosity.VERY_VERBOSE,
        logging.INFO: Verbosity.VERBOSE,
        logging.WARNING: Verbosity.NORMAL,
        logging.ERROR: Verbosity.QUIET,
        logging.CRITICAL: Verbosity.QUIET,
    }

    def __init__(self, output: "Output") -> None:
        super().__init__(logging.NOTSET)
        self.output = output

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)
            return

        verbosity = self.VERBOSITY.get(record.levelno, Verbosity.NORMAL)
        self.output.write_line(msg, verbosity=verbosity)


class Formatter(logging.Formatter):
    """Translates internal expression into cleo's format."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

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
            msg = f"[secrets.env] <debug>{msg}</debug>"

        return msg

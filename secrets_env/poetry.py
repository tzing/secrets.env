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
from secrets_env.utils import removeprefix

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

        secrets = secrets_env.load_secrets()
        for key, value in secrets.items():
            os.environ[key] = value

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
        output.formatter.set_style("warning", Style("light_gray", options=["dark"]))

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

        if msg.startswith("<!important>"):
            verbosity = Verbosity.QUIET
        else:
            verbosity = self.VERBOSITY.get(record.levelno, Verbosity.NORMAL)

        self.output.write_line(msg, verbosity=verbosity)


class CleoFormatter(logging.Formatter):
    """Translates internal expression into cleo's format."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        msg = removeprefix(msg, "<!important>")

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

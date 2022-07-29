import logging
import typing

from cleo.events.console_events import COMMAND
from cleo.formatters.style import Style
from cleo.io.outputs.output import Verbosity
from poetry.console.commands.run import RunCommand
from poetry.console.commands.shell import ShellCommand
from poetry.plugins.application_plugin import ApplicationPlugin

if typing.TYPE_CHECKING:
    from cleo.events.console_command_event import ConsoleCommandEvent
    from cleo.events.event_dispatcher import EventDispatcher
    from cleo.io.io import IO
    from poetry.console.application import Application


class Vault2EnvPlugin(ApplicationPlugin):
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

        # set output format
        formatter = event.io.output.formatter
        formatter.set_style("debug", Style("white"))
        formatter.set_style("warning", Style("yellow", options=["bold"]))

        # send internal message to cleo
        # see docstring in Handler for details
        handler = Handler(event.io)
        handler.setFormatter(Formatter())

        logger = logging.getLogger("vault2env")
        logger.setLevel(logging.NOTSET)
        logger.propagate = False
        logger.addHandler(handler)


class Handler(logging.Handler):
    """Custom handler that use cleo's IO to show message.

    Vault2env uses logging module internally for showing messages to users.
    By default, cleo hides the logs unless `-vv` (VERY_VERBOSE) is set, it made
    it harder to show warnings or errors.

    This class receives all logs from vault2env and (re)assign the verbosity
    level. Besides, it colored the output using our custom Formatter, powered
    with cleo's formatter.
    """

    def __init__(self, io: "IO") -> None:
        super().__init__(logging.NOTSET)
        self.io = io

    def emit(self, record: logging.LogRecord) -> None:
        # get verbosity base on log level
        verbosity = Verbosity.NORMAL
        if record.levelno <= logging.INFO:
            verbosity = Verbosity.VERBOSE

        # format message
        try:
            msg = self.format(record)
        except Exception:
            self.handleError(record)

        # send
        self.io.write_line(msg, verbosity=verbosity)


class Formatter(logging.Formatter):
    """Custom formatter that translates internal expression into cleo's format."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        # tag translate
        # uses builtin tags for aligning the appearance with poetry and other plugins
        msg = msg.replace("<em>", "<info>").replace("</em>", "</info>")
        msg = msg.replace("<data>", "<comment>").replace("</data>", "</comment>")

        # add color
        if record.levelno >= logging.ERROR:
            msg = f"<error>{msg}</error>"
        elif record.levelno >= logging.WARNING:
            msg = f"<warning>{msg}</warning>"
        elif record.levelno <= logging.DEBUG:
            msg = f"<debug>{msg}</debug>"

        return msg

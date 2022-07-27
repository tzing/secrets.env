import typing

from cleo.events.console_events import COMMAND
from poetry.console.commands.run import RunCommand
from poetry.console.commands.shell import ShellCommand
from poetry.plugins.application_plugin import ApplicationPlugin

if typing.TYPE_CHECKING:
    from cleo.events.console_command_event import ConsoleCommandEvent
    from cleo.events.event_dispatcher import EventDispatcher
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

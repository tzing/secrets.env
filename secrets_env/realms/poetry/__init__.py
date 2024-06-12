"""Adapt poetry's plugin framework to automatically load secrets on specific
poetry commands.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, cast

from cleo.events.console_command_event import ConsoleCommandEvent
from cleo.events.console_events import COMMAND
from poetry.plugins.application_plugin import ApplicationPlugin

import secrets_env
from secrets_env.exceptions import ConfigError
from secrets_env.realms.poetry.cleo import setup_output
from secrets_env.utils import is_secrets_env_active

if TYPE_CHECKING:
    from cleo.events.event import Event
    from cleo.events.event_dispatcher import EventDispatcher
    from poetry.console.application import Application

logger = logging.getLogger(__name__)


class SecretsEnvPlugin(ApplicationPlugin):
    def activate(self, application: Application) -> None:
        if application.event_dispatcher:
            application.event_dispatcher.add_listener(COMMAND, self.load_values)

    def load_values(
        self,
        event: Event,
        event_name: str,
        dispatcher: EventDispatcher,
    ) -> None:
        event = cast(ConsoleCommandEvent, event)
        if event.command.name not in ("run", "shell"):
            return

        setup_output(event.io.output)
        logger.debug("Start secrets.env poetry plugin")

        if is_secrets_env_active():
            logger.warning("Secrets.env is already active. Skip loading values.")
            return

        try:
            values = secrets_env.read_values(config=None, strict=False)
        except ConfigError:
            return

        for name, value in values.items():
            os.environ[name] = value

        if values:
            # mark secrets.env is active when values are loaded
            os.environ["SECRETS_ENV_ACTIVE"] = "1"

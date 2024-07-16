from __future__ import annotations

import logging
import sys
import typing

import secrets_env.utils

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import NoReturn

logger = logging.getLogger(__name__)


class Shell:
    """Base class for providing shell activation."""

    def __init__(self, shell_path: Path) -> None:
        self.shell_path = shell_path

    def activate(self, environ: dict[str, str]) -> NoReturn:
        """Activate the shell with the specified environment variables."""
        logger.info("Spawning shell")
        logger.debug("Activating shell by '%s' class", type(self).__name__)

        with secrets_env.utils.inject_environs(environ):
            code = self.handover()

        sys.exit(code)

    def handover(self) -> int | None:
        """
        Perform the handover to the shell.
        This method should only be called by the `activate` method and should not return.
        """
        raise NotImplementedError

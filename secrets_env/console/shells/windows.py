from __future__ import annotations

import logging
import subprocess

from secrets_env.console.shells.base import Shell

logger = logging.getLogger(__name__)


class WindowsShell(Shell):
    def handover(self) -> int:
        logger.debug("Run %s as subprocess", self.shell_path)
        result = subprocess.run(
            str(self.shell_path),
            shell=True,
            text=False,
        )
        return result.returncode

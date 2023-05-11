"""An helper module that wraps `Teleport CLI`_ (``tsh``) and get connection
information from it.

.. _Teleport CLI: https://goteleport.com/docs/reference/cli/
"""
import dataclasses
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from secrets_env.exceptions import DependencyError

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


def call_teleport(
    args: Iterable[str],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    encoding: str = "utf-8",
) -> subprocess.CompletedProcess[str]:
    """Forwards args to tsh"""
    cmd = [TELEPORT_APP_NAME, *args]
    logger.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, stdout=stdout, stderr=stderr, encoding=encoding)


def print_version() -> bool:
    """Print Teleport version to log."""
    res = call_teleport(["version"])
    if res.returncode != 0:
        return False
    for line in res.stdout.splitlines():
        logger.debug("< %s", line)
    return True

"""An helper module that wraps `Teleport CLI`_ (``tsh``) and get connection
information from it.

.. _Teleport CLI: https://goteleport.com/docs/reference/cli/
"""
import dataclasses
import io
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple, TypedDict

from secrets_env.exceptions import AuthenticationError, DependencyError, InternalError

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


def _command(*args: Iterable[str]) -> list[str]:
    """Build command and log it"""
    cmd = [TELEPORT_APP_NAME, *args]
    logger.debug("$ %s", " ".join(cmd))
    return cmd


def call_version() -> bool:
    """Call version command and print it to log."""
    res = subprocess.run(
        _command("version"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
    )
    if res.returncode != 0:
        return False
    for line in res.stdout.splitlines():
        logger.debug("< %s", line)
    return True

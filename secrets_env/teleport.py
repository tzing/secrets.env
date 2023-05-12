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
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TypedDict

from secrets_env.exceptions import AuthenticationError, DependencyError, InternalError

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


def _command(*args: Iterable[str]) -> List[str]:
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


def call_app_config(app: str) -> Dict[str, str]:
    res = subprocess.run(
        _command("app", "config", "--format=json", app),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if res.returncode != 0:
        return {}
    return json.loads(res.stdout)

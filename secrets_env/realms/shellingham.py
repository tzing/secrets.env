from __future__ import annotations

import logging
import os
from pathlib import Path

from secrets_env.exceptions import OperationError

logger = logging.getLogger(__name__)


def detect_shell() -> tuple[str, Path]:
    """
    Detect the current shell.

    Returns
    -------
    shell : str
        Shell name.
    path : Path
        Path to the shell executable.

    Raises
    ------
    OperationError
        If the shell cannot be detected.
    """
    # try to detect shell via shellingham
    if pair := _detect_shell_via_shellingham():
        return pair

    # fallback to default
    raw_shell_path = None
    if os.name == "posix":
        raw_shell_path = os.getenv("SHELL")
    elif os.name == "nt":
        raw_shell_path = os.getenv("COMSPEC")

    if not raw_shell_path:
        raise OperationError("Cannot detect shell")

    shell_path = Path(raw_shell_path)
    logger.debug("Use default shell: %s", shell_path)
    return shell_path.stem.lower(), shell_path


def _detect_shell_via_shellingham() -> tuple[str, Path] | None:
    try:
        import shellingham
    except ImportError:
        return None

    try:
        shell, path = shellingham.detect_shell()
        logger.debug("Detect shell: %s", path)
        return shell, Path(path)
    except shellingham.ShellDetectionFailure:
        return None

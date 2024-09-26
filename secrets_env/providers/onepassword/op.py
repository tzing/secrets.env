from __future__ import annotations

import functools
import logging
import shutil
import subprocess
import typing

from pydantic import Field, FilePath

from secrets_env.provider import Provider
from secrets_env.realms.subprocess import check_output

if typing.TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class OnePasswordCliProvider(Provider):
    """
    Read secrets from 1Password using the `op` CLI tool.
    """

    type = "1password-cli"

    op_path: FilePath | None = Field(
        alias="op-path",
        default_factory=lambda: shutil.which("op"),
        validate_default=True,
    )


@functools.lru_cache(1)
def call_version(path: Path) -> None:
    """Call version command and print it to log."""
    try:
        check_output([str(path), "--version"])
    except subprocess.CalledProcessError:
        raise RuntimeError("Internal error on invoking op") from None

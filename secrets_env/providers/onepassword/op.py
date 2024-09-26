from __future__ import annotations

import functools
import logging
import re
import shutil
import subprocess
import typing

from pydantic import Field, FilePath

from secrets_env.provider import Provider
from secrets_env.providers.onepassword.models import ItemObject
from secrets_env.realms.subprocess import check_output

if typing.TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

op_log_prefix_pattern = re.compile(
    r"^\[(?P<level>\w+)\] (?P<datetime>\d+/\d+/\d+ \d+:\d+:\d+) "
)


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
def call_version(op_path: Path) -> None:
    """Call version command and print it to log."""
    try:
        check_output([str(op_path), "--version"])
    except subprocess.CalledProcessError:
        raise RuntimeError("Internal error on invoking op") from None


def get_item(op_path: Path, ref: str) -> ItemObject:
    """
    Run the op command to get an item from 1Password.
    """
    try:
        output = check_output(
            [str(op_path), "item", "get", ref, "--format", "json"],
            level_output=None,
            level_error=logging.DEBUG,
        )
    except subprocess.CalledProcessError as e:
        msg = op_log_prefix_pattern.sub("", e.stderr.rstrip())
        raise LookupError(msg) from None

    return ItemObject.model_validate_json(output)

from __future__ import annotations

import functools
import logging
import re
import shutil
import subprocess
from pathlib import Path

from pydantic import Field, FilePath

from secrets_env.exceptions import UnsupportedError
from secrets_env.provider import Provider, Request
from secrets_env.providers.onepassword.models import ItemObject, OpRequest
from secrets_env.realms.subprocess import check_output
from secrets_env.utils import cache_query_result

logger = logging.getLogger(__name__)

op_log_prefix_pattern = re.compile(
    r"^\[(?P<level>\w+)\] (?P<datetime>\d+/\d+/\d+ \d+:\d+:\d+) "
)


def get_op_path() -> Path | None:
    if path := shutil.which("op"):
        return Path(path)


class OnePasswordCliProvider(Provider):
    """
    Read secrets from 1Password using the `op` CLI tool.
    """

    type = "1password-cli"

    bin: FilePath | None = Field(default_factory=get_op_path, validate_default=True)

    @cache_query_result()
    def _get_item_(self, ref: str) -> ItemObject:
        if not self.bin:
            raise UnsupportedError("op command is not installed or accessible")

        call_version(self.bin)  # log version on first call

        return get_item(self.bin, ref)

    @cache_query_result()
    def _get_value_(self, spec: Request) -> str:
        request = OpRequest.model_validate(spec.model_dump(exclude_none=True))
        item = self._get_item_(request.ref)
        field = item.get_field(request.field)

        if field.value is None:
            raise LookupError(f'Field "{request.field}" has no value')

        return field.value.get_secret_value()


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

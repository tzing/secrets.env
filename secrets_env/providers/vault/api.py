from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Literal

import httpx
from pydantic import BaseModel

from secrets_env.utils import get_httpx_error_reason, log_httpx_response

logger = logging.getLogger(__name__)


class RawMountMetadata(BaseModel):
    """
    {
        "data": {
            "options": {"version": "1"},
            "path": "secrets/",
            "type": "kv",
        }
    }
    """

    data: DataBlock

    class DataBlock(BaseModel):

        options: _OptionBlock
        path: str
        type: str

        class _OptionBlock(BaseModel):
            version: str


class MountMetadata(BaseModel):
    """Represents a mount point and KV engine version to a secret."""

    path: str
    version: Literal[1, 2]


def get_mount(client: httpx.Client, path: str) -> MountMetadata | None:
    """Get mount point and KV engine version to a secret.

    See also
    --------
    Vault HTTP API
        https://developer.hashicorp.com/vault/api-docs/system/internal-ui-mounts
    consul-template
        https://github.com/hashicorp/consul-template/blob/v0.29.1/dependency/vault_common.go#L294-L357
    """
    try:
        resp = client.get(f"/v1/sys/internal/ui/mounts/{path}")
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
            raise
        logger.error("Error occurred during checking metadata for %s: %s", path, reason)
        return

    if resp.is_success:
        parsed = RawMountMetadata.model_validate_json(resp.read())
        return MountMetadata(
            path=parsed.data.path,
            version=int(parsed.data.options.version),  # type: ignore[reportArgumentType]
        )

    elif resp.status_code == HTTPStatus.NOT_FOUND:
        # 404 is expected on an older version of vault, default to version 1
        # https://github.com/hashicorp/consul-template/blob/v0.29.1/dependency/vault_common.go#L310-L311
        return MountMetadata(path="", version=1)

    logger.error("Error occurred during checking metadata for %s", path)
    log_httpx_response(logger, resp)
    return

from __future__ import annotations

import logging
import typing
from typing import Literal

from pydantic import BaseModel, model_validator

from secrets_env.provider import Provider
from secrets_env.providers.teleport.config import TeleportUserConfig

if typing.TYPE_CHECKING:
    from typing import Self

    from secrets_env.provider import RequestSpec
    from secrets_env.providers.teleport.config import TeleportConnectionParameter

logger = logging.getLogger(__name__)


class TeleportRequestSpec(BaseModel):
    field: Literal["uri", "ca", "cert", "key", "cert+key"]
    format: Literal["path", "pem"] = "path"

    @model_validator(mode="before")
    @classmethod
    def _accept_shortcut(cls, data: RequestSpec | Self) -> dict[str, str] | Self:
        if isinstance(data, str):
            return {"field": data}
        return data


class TeleportProvider(Provider, TeleportUserConfig):
    """Read certificates from Teleport."""

    type = "teleport"

    def get(self, raw_spec: RequestSpec) -> str:
        spec = TeleportRequestSpec.model_validate(raw_spec)
        param = self.get_connection_param()

        if spec.field == "uri":
            return param.uri

        elif spec.field == "ca":
            return get_ca(param, spec.format)


def get_ca(param: TeleportConnectionParameter, fmt: Literal["path", "pem"]) -> str:
    if param.ca is None:
        raise LookupError("CA is not available")
    if fmt == "path":
        return str(param.path_ca)
    elif fmt == "pem":
        return param.ca.decode()

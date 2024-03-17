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

    def get(self, spec: RequestSpec) -> str:
        ps = TeleportRequestSpec.model_validate(spec)

        if ps.field == "uri":
            return self.connection_param.uri
        elif ps.field == "ca":
            return get_ca(self.connection_param, ps.format)
        elif ps.field == "cert":
            if ps.format == "path":
                return str(self.connection_param.path_cert)
            elif ps.format == "pem":
                return self.connection_param.cert.decode()
        elif ps.field == "key":
            if ps.format == "path":
                return str(self.connection_param.path_key)
            elif ps.format == "pem":
                return self.connection_param.key.decode()
        elif ps.field == "cert+key":
            if ps.format == "path":
                return str(self.connection_param.path_cert_and_key)
            elif ps.format == "pem":
                return self.connection_param.cert_and_key.decode()

        raise RuntimeError


def get_ca(param: TeleportConnectionParameter, fmt: Literal["path", "pem"]) -> str:
    if param.ca is None:
        raise LookupError("CA is not available")
    if fmt == "path":
        return str(param.path_ca)
    elif fmt == "pem":
        return param.ca.decode()

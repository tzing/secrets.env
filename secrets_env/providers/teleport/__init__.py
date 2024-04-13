from __future__ import annotations

import logging
import typing
from typing import Literal

from pydantic import BaseModel, model_validator

from secrets_env.provider import Provider, Request
from secrets_env.providers.teleport.config import TeleportUserConfig

if typing.TYPE_CHECKING:
    from secrets_env.providers.teleport.config import TeleportConnectionParameter

logger = logging.getLogger(__name__)


class TeleportRequestSpec(BaseModel):
    field: Literal["uri", "ca", "cert", "key", "cert+key"]
    format: Literal["path", "pem"] = "path"

    @model_validator(mode="before")
    @classmethod
    def _accept_shortcut(cls, data):
        if isinstance(data, dict):
            if not data.get("field"):
                return {"field": data.get("value")}
        return data


class TeleportProvider(Provider, TeleportUserConfig):
    """Read certificates from Teleport."""

    type = "teleport"

    def _get_value_(self, spec: Request) -> str:
        ps = TeleportRequestSpec.model_validate(spec.model_dump(exclude_none=True))

        if ps.field == "uri":
            return self.connection_param.uri
        elif ps.field == "ca":
            return get_ca(self.connection_param, ps.format)
        elif ps.field == "cert":
            if ps.format == "path":
                return str(self.connection_param.path_cert)
            elif ps.format == "pem":
                return self.connection_param.cert.get_secret_value().decode()
        elif ps.field == "key":
            if ps.format == "path":
                return str(self.connection_param.path_key)
            elif ps.format == "pem":
                return self.connection_param.key.get_secret_value().decode()
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
        return param.ca.get_secret_value().decode()

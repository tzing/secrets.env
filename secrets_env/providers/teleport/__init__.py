from __future__ import annotations

import typing

import pydantic

from secrets_env.exceptions import ConfigError
from secrets_env.providers.teleport.provider import TeleportProvider  # noqa: F401

if typing.TYPE_CHECKING:
    from secrets_env.provider import Provider


ADAPTER_PREFIX = "teleport+"


def get_adapted_provider(type_: str, data: dict) -> Provider:
    from .adapters import get_adapter
    from .config import TeleportUserConfig  # noqa: TCH001

    class TeleportAdapterConfig(pydantic.BaseModel):
        """Config layout for using Teleport as an adapter."""

        teleport: TeleportUserConfig

    iname = type_.lower()
    if not iname.startswith(ADAPTER_PREFIX):
        raise ConfigError("Not a Teleport compatible provider: {}", type_)

    subtype = type_[len(ADAPTER_PREFIX) :]
    factory = get_adapter(subtype)

    # get connection parameter
    app_param = TeleportAdapterConfig.model_validate(data)
    conn_param = app_param.teleport.connection_param

    # forward parameters to corresponding provider
    return factory(subtype, data, conn_param)

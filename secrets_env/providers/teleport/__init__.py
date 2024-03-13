from __future__ import annotations

import typing

import pydantic

from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase
    from secrets_env.providers.teleport.provider import TeleportProvider

ADAPTER_PREFIX = "teleport+"


def get_provider(type_: str, data: dict) -> TeleportProvider:
    from .config import TeleportUserConfig
    from .provider import TeleportProvider

    cfg = TeleportUserConfig.model_validate(data)
    return TeleportProvider(config=cfg)


def get_adapted_provider(type_: str, data: dict) -> ProviderBase:
    from .adapters import get_adapter
    from .config import TeleportUserConfig  # noqa: TCH001
    from .helper import get_connection_param

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
    conn_param = get_connection_param(app_param.teleport)

    # forward parameters to corresponding provider
    return factory(subtype, data, conn_param)

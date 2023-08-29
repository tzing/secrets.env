import typing

from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase
    from secrets_env.providers.teleport.provider import TeleportProvider

ADAPTER_PREFIX = "teleport+"


def get_provider(type_: str, data: dict) -> "TeleportProvider":
    from .config import parse_source_config
    from .provider import TeleportProvider

    cfg = parse_source_config(data)
    return TeleportProvider(**cfg)


def get_adapted_provider(type_: str, data: dict) -> "ProviderBase":
    from .adapters import get_adapter
    from .config import parse_adapter_config
    from .helper import get_connection_info

    iname = type_.lower()
    if not iname.startswith(ADAPTER_PREFIX):
        raise ConfigError("Not a Teleport compatible provider: {}", type_)

    subtype = type_[len(ADAPTER_PREFIX) :]
    factory = get_adapter(subtype)

    # get connection parameter
    app_param = parse_adapter_config(data)
    conn_info = get_connection_info(app_param)

    # forward parameters to corresponding provider
    return factory(subtype, data, conn_info)

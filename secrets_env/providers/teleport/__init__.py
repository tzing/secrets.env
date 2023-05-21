import typing

from secrets_env.exceptions import ConfigError

from . import adapters, config, helper

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

ADAPTER_PREFIX = "teleport+"


def get_provider(type_: str, data: dict) -> "ProviderBase":
    if not type_.startswith(ADAPTER_PREFIX):
        raise ConfigError("Not a Teleport integrated provider: {}", type_)

    # ensure the adopted provider type is supportted
    adopted_type = type_[len(ADAPTER_PREFIX) :]
    adopter = adapters.get_adapter(adopted_type)

    # get connection parameter
    app_param = config.parse_config(data)
    conn_info = helper.get_connection_info(app_param)

    # forward parameters to corresponding provider
    return adopter(adopted_type, data, conn_info)

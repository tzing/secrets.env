import typing

from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

PROVIDER_NAME = "teleport"
ADAPTER_PREFIX = "teleport+"


def get_provider(type_: str, data: dict) -> "ProviderBase":
    iname = type_.lower()
    if iname == PROVIDER_NAME:
        raise NotImplementedError

    if iname.startswith(ADAPTER_PREFIX):
        from .adapters import handle

        subtype = type_[len(ADAPTER_PREFIX) :]
        return handle(subtype, data)

    raise ConfigError("Not a Teleport compatible provider: {}", type_)

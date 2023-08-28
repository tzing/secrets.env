import typing

import secrets_env.exceptions

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

DEFAULT_PROVIDER = "vault"


def get_provider(data: dict) -> "ProviderBase":
    type_ = data.get("type", DEFAULT_PROVIDER)
    type_lower = type_.lower()

    # fmt: off
    if type_lower == "null":
        from . import null
        return null.get_provider(type_, data)
    if type_lower == "plain":
        from . import plain
        return plain.get_provider(type_, data)
    if type_lower == "teleport":
        from . import teleport
        return teleport.get_provider(type_, data)
    if type_lower == "vault":
        from . import vault
        return vault.get_provider(type_, data)
    if type_lower.startswith("teleport+"):
        from . import teleport
        return teleport.get_adapted_provider(type_, data)
    # fmt: on

    raise secrets_env.exceptions.ConfigError("Unknown provider type {}", type_)

import typing

import secrets_env.exceptions

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

DEFAULT_PROVIDER = "vault"


def get_provider(data: dict) -> "ProviderBase":
    type_raw = data.get("type", DEFAULT_PROVIDER)
    type_ = type_raw.lower()

    # builtin first
    # fmt: off
    if type_ == "null":
        from . import null
        return null.get_provider(type_, data)
    if type_ == "vault":
        from . import vault
        return vault.get_provider(type_, data)
    # fmt: on

    raise secrets_env.exceptions.ConfigError("Unknown provider type {}", type_raw)

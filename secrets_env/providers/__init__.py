import typing

import secrets_env.exceptions
import secrets_env.hooks

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

DEFAULT_PROVIDER = "vault"


def get_provider(data: dict) -> "ProviderBase":
    type_raw = data.get("type", DEFAULT_PROVIDER)
    type_ = type_raw.lower()

    # builtin first
    # fmt: off
    if type_ == "vault":
        from . import vault
        return vault.get_provider(type_, data)
    # fmt: on

    # call hook
    hook = secrets_env.hooks.get_hooks()
    if reader := hook.get_provider(type=type_, data=data):
        return reader

    raise secrets_env.exceptions.ConfigError("Unknown provider type {}", type_raw)

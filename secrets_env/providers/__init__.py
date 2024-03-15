from __future__ import annotations

import logging
import typing

if typing.TYPE_CHECKING:
    from secrets_env.provider import Provider

DEFAULT_PROVIDER = "vault"

logger = logging.getLogger(__name__)


def get_provider(config: dict) -> Provider:
    """
    Returns a provider instance based on the configuration.

    Raises
    ------
    ValueError
        If the provider type is not recognized.
    ValidationError
        If the provider configuration is invalid.
    """
    type_ = config.get("type")
    if not type_:
        type_ = DEFAULT_PROVIDER
        logger.warning("Provider type unspecified, using default: %s", type_)

    itype = type_.lower()

    # fmt: off
    if itype == "null":
        from secrets_env.providers.null import NullProvider
        return NullProvider.model_validate(config)
    if itype == "plain":
        from secrets_env.providers.plain import PlainTextProvider
        return PlainTextProvider.model_validate(config)
    if itype == "teleport":
        from secrets_env.providers.teleport import TeleportProvider
        return TeleportProvider.model_validate(config)
    # fmt: on
    # TODO vault
    # TODO adapters

    raise ValueError(f"Unknown provider type {type_}")

from __future__ import annotations

import logging
import typing

from pydantic_core import ValidationError

if typing.TYPE_CHECKING:
    from secrets_env.provider import Provider

DEFAULT_PROVIDER = "vault"

logger = logging.getLogger(__name__)


def get_provider(config: dict) -> Provider:
    """
    Returns a provider instance based on the configuration.

    Raises
    ------
    ValidationError
        If the provider configuration is invalid.
    """
    type_ = config.get("type")
    if not type_:
        type_ = DEFAULT_PROVIDER
        logger.warning("Provider type unspecified, using default: %s", type_)

    itype = type_.lower()

    # fmt: off
    if itype == "debug":
        from secrets_env.providers.debug import DebugProvider
        return DebugProvider.model_validate(config)
    if itype == "plain":
        from secrets_env.providers.plain import PlainTextProvider
        return PlainTextProvider.model_validate(config)
    if itype == "teleport":
        from secrets_env.providers.teleport import TeleportProvider
        return TeleportProvider.model_validate(config)
    if itype == "teleport+vault":
        logger.warning("Type 'teleport+vault' is deprecated, use 'vault' instead")
        from secrets_env.providers.vault import VaultKvProvider
        return VaultKvProvider.model_validate(config)
    if itype == "vault":
        from secrets_env.providers.vault import VaultKvProvider
        return VaultKvProvider.model_validate(config)
    # fmt: on

    raise ValidationError.from_exception_data(
        title="Provider",
        line_errors=[
            {
                "type": "value_error",
                "loc": ("type",),
                "input": type_,
                "ctx": {
                    "error": f"Unknown provider type '{type_}'",
                },
            }
        ],
    )

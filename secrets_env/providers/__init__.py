from __future__ import annotations

import logging
import typing
import warnings

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
        warnings.warn(
            f"Provider type unspecified, using default: {DEFAULT_PROVIDER}",
            UserWarning,
            stacklevel=1,
        )

    itype = type_.lower()

    # fmt: off
    if itype == "1password:op":
        from secrets_env.providers.onepassword.op import OnePasswordCliProvider
        return OnePasswordCliProvider.model_validate(config)
    if itype == "debug":
        from secrets_env.providers.debug import DebugProvider
        return DebugProvider.model_validate(config)
    if itype == "kubernetes:kubectl":
        from secrets_env.providers.kubernetes.kubectl import KubectlProvider
        return KubectlProvider.model_validate(config)
    if itype == "plain":
        from secrets_env.providers.plain import PlainTextProvider
        return PlainTextProvider.model_validate(config)
    if itype == "teleport":
        from secrets_env.providers.teleport import TeleportProvider
        return TeleportProvider.model_validate(config)
    if itype == "teleport+vault":
        warnings.warn(
            "Type 'teleport+vault' is deprecated, use 'vault' instead",
            DeprecationWarning,
            stacklevel=1,
        )
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

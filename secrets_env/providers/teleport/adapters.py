from __future__ import annotations

import logging
import typing

from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.provider import Provider
    from secrets_env.providers.teleport.config import TeleportConnectionParameter

    AdapterType = typing.Callable[[str, dict, TeleportConnectionParameter], Provider]

logger = logging.getLogger(__name__)


def get_adapter(name: str) -> AdapterType:
    iname = name.lower()
    if iname == "vault":
        return adapt_vault_provider

    raise ConfigError("Unknown provider type {}", name)


def adapt_vault_provider(
    type_: str, data: dict, param: TeleportConnectionParameter
) -> Provider:
    assert isinstance(data, dict)
    from secrets_env.providers import vault

    # url
    if (url := data.get("url")) and url != param.uri:
        logger.warning("Overwrite source.url to %s", param.uri)

    data["url"] = param.uri
    logger.debug("Set Vault URL to %s", param.uri)

    # ca
    tls: dict = data.setdefault("tls", {})
    if param.path_ca:
        tls["ca_cert"] = param.path_ca
        logger.debug("Set Vault CA to %s", param.path_ca)

    # cert
    tls["client_cert"] = param.path_cert
    logger.debug("Set Vault client cert to %s", param.path_cert)

    # key
    tls["client_key"] = param.path_key
    logger.debug("Set Vault client key to %s", param.path_key)

    return vault.get_provider(type_, data)

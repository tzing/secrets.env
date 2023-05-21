import logging
import typing

from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase
    from secrets_env.providers.teleport.helper import AppConnectionInfo

AdapterType = typing.Callable[[str, dict, "AppConnectionInfo"], "ProviderBase"]

logger = logging.getLogger(__name__)


def get_adapter(type_: str) -> AdapterType:
    if type_ == "vault":
        return adapt_vault_provider

    raise ConfigError("Unknown provider type {}", type_)


def adapt_vault_provider(type_: str, data: dict, conn_info: "AppConnectionInfo"):
    assert isinstance(data, dict)
    from secrets_env.providers import vault

    # url
    if (url := data.get("url")) and url != conn_info.uri:
        logger.warning("Overwrite source.url to %s", conn_info.uri)

    data["url"] = conn_info.uri
    logger.debug("Set Vault URL to %s", conn_info.uri)

    # ca
    tls: dict = data.setdefault("tls", {})
    if conn_info.path_ca:
        tls["ca_cert"] = conn_info.path_ca
        logger.debug("Set Vault CA to %s", conn_info.path_ca)

    # cert
    tls["client_cert"] = conn_info.path_cert
    logger.debug("Set Vault client cert to %s", conn_info.path_cert)

    # key
    tls["client_key"] = conn_info.path_key
    logger.debug("Set Vault client key to %s", conn_info.path_key)

    return vault.get_provider(type_, data)

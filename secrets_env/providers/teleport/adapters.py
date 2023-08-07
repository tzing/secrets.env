import logging
import typing

from secrets_env.exceptions import ConfigError
from secrets_env.providers.teleport.config import parse_adapter_config
from secrets_env.providers.teleport.helper import get_connection_info

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase
    from secrets_env.providers.teleport.helper import AppConnectionInfo

AdapterType = typing.Callable[[str, dict, "AppConnectionInfo"], "ProviderBase"]

logger = logging.getLogger(__name__)


def handle(subtype: str, data: dict) -> "ProviderBase":
    # ensure the adopted provider type is supportted
    adapter = get_adapter(subtype)

    # get connection parameter
    app_param = parse_adapter_config(data)
    conn_info = get_connection_info(app_param)

    # forward parameters to corresponding provider
    return adapter(subtype, data, conn_info)


def get_adapter(name: str) -> AdapterType:
    iname = name.lower()
    if iname == "vault":
        return adapt_vault_provider

    raise ConfigError("Unknown provider type {}", name)


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

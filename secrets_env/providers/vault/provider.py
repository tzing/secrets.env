from __future__ import annotations

import logging
import typing
from functools import cached_property

import httpx
from pydantic import BaseModel, model_validator

import secrets_env.version
from secrets_env.provider import Provider
from secrets_env.providers.vault.config import VaultUserConfig

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec

logger = logging.getLogger(__name__)


class VaultKvProvider(Provider, VaultUserConfig):
    """Read secrets from Hashicorp Vault KV engine."""

    type = "vault"

    @cached_property
    def client(self) -> httpx.Client:
        """Returns HTTP client."""
        logger.debug(
            "Vault client initialization requested. URL= %s, Auth type= %s",
            self.url,
            self.auth.method,
        )
        return create_http_client(self)


def create_http_client(config: VaultUserConfig) -> httpx.Client:
    logger.debug(
        "Vault client initialization requested. URL= %s, Auth type= %s",
        config.url,
        config.auth.method,
    )

    client_params = {
        "base_url": str(config.url),
        "headers": {
            "Accept": "application/json",
            "User-Agent": (
                f"secrets.env/{secrets_env.version.__version__} "
                f"python-httpx/{httpx.__version__}"
            ),
        },
    }

    if config.proxy:
        logger.debug("Proxy is set: %s", config.proxy)
        client_params["proxy"] = str(config.proxy)
    if config.tls.ca_cert:
        logger.debug("CA cert is set: %s", config.tls.ca_cert)
        client_params["verify"] = config.tls.ca_cert
    if config.tls.client_cert and config.tls.client_key:
        cert_pair = (config.tls.client_cert, config.tls.client_key)
        logger.debug("Client cert pair is set: %s ", cert_pair)
        client_params["cert"] = cert_pair
    elif config.tls.client_cert:
        logger.debug("Client cert is set: %s", config.tls.client_cert)
        client_params["cert"] = config.tls.client_cert

    return httpx.Client(**client_params)

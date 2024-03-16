from __future__ import annotations

import logging
import typing
from functools import cached_property

import httpx
from pydantic import BaseModel, model_validator

import secrets_env.version
from secrets_env.exceptions import AuthenticationError
from secrets_env.provider import Provider
from secrets_env.providers.vault.config import VaultUserConfig
from secrets_env.utils import get_httpx_error_reason, log_httpx_response

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec
    from secrets_env.providers.vault.auth import Auth

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

        client = create_http_client(self)
        client.headers["X-Vault-Token"] = get_token(client, self.auth)

        return client


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


def get_token(client: httpx.Client, auth: Auth) -> str:
    """
    Request a token from the Vault server and verify it.

    Raises
    ------
    AuthenticationError
        If the token cannot be retrieved or is invalid.
    """
    # login
    try:
        token = auth.login(client)
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
            raise
        raise AuthenticationError("Encounter {} while retrieving token", reason) from e

    if not token:
        raise AuthenticationError("Absence of token information")

    # verify
    if not is_authenticated(client, token):
        raise AuthenticationError("Invalid token")

    return token


def is_authenticated(client: httpx.Client, token: str) -> bool:
    """Check is a token is authenticated.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/token
    """
    logger.debug("Validate token for %s", client.base_url)

    resp = client.get("/v1/auth/token/lookup-self", headers={"X-Vault-Token": token})
    if resp.is_success:
        return True

    logger.debug(
        "Token verification failed. Code= %d (%s). Msg= %s",
        resp.status_code,
        resp.reason_phrase,
        resp.json(),
    )
    return False

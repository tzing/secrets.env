import logging
import os
import re
import typing
from http import HTTPStatus
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Tuple, Union

import httpx

from secrets_env.exceptions import AuthenticationError, TypeError
from secrets_env.reader import ReaderBase
from secrets_env.utils import get_httpx_error_reason

if typing.TYPE_CHECKING:
    from secrets_env.providers.vault.auth.base import Auth
    from secrets_env.providers.vault.config import CertTypes

logger = logging.getLogger(__name__)


class KVReader(ReaderBase):
    """Read secrets from Vault KV engine."""

    def __init__(
        self,
        url: str,
        auth: "Auth",
        ca_cert: Optional["Path"] = None,
        client_cert: Optional["CertTypes"] = None,
    ) -> None:
        self.url = url
        self.auth = auth
        self.ca_cert = ca_cert
        self.client_cert = client_cert

        self._client: Optional[httpx.Client] = None
        self._secrets: Dict[Tuple[str, str], Optional[str]] = {}

    @property
    def client(self) -> httpx.Client:
        """Returns HTTP client."""
        if self._client:
            return self._client

        logger.debug(
            "Vault client initialization requested. URL= %s, Auth type= %s",
            self.url,
            self.auth.method(),
        )

        # initialize client
        client = create_client(self.url, self.ca_cert, self.client_cert)

        # get token
        try:
            token = self.auth.login(client)
        except httpx.HTTPError as e:
            if not (reason := get_httpx_error_reason(e)):
                raise
            raise AuthenticationError("{} during get token", reason)

        if not token:
            raise AuthenticationError("Token is not populated")

        # verify token
        if is_authenticated(client, token):
            client.headers["X-Vault-Token"] = token
        else:
            raise AuthenticationError("Invalid token")

        self._client = client
        return client

    def get(self, spec: Union[Dict[str, str], str]) -> str:
        return super().get(spec)


def create_client(
    base_url: str, ca_cert: Optional["Path"], client_cert: Optional["CertTypes"]
):
    """Initialize a client."""
    if not isinstance(base_url, str):
        raise TypeError("Expect str for base_url, got {}", type(base_url).__name__)
    if ca_cert is not None and not isinstance(ca_cert, os.PathLike):
        raise TypeError("Expect path-like for ca_cert, got {}", type(ca_cert).__name__)
    if client_cert is not None and not isinstance(client_cert, (os.PathLike, tuple)):
        raise TypeError(
            "Expect path-like for client_cert, got {}", type(client_cert).__name__
        )

    logger.debug("Creating client to %s", base_url)

    params = {
        "base_url": base_url,
        "http2": True,
    }

    if ca_cert:
        logger.debug("CA installed: %s", ca_cert)
        params["verify"] = ca_cert
    elif client_cert:
        logger.debug("Client side certificate file installed: %s", client_cert)
        params["cert"] = client_cert

    return httpx.Client(**params)


def is_authenticated(client: httpx.Client, token: str):
    """Check is a token is authenticated.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/token
    """
    if not isinstance(client, httpx.Client):
        raise TypeError("Expect httpx.Client for client, got {}", type(client).__name__)
    if not isinstance(token, str):
        raise TypeError("Expect str for path, got {}", type(token).__name__)

    logger.debug("Validate token for %s", client.base_url)

    resp = client.get("/v1/auth/token/lookup-self", headers={"X-Vault-Token": token})
    if resp.status_code != HTTPStatus.OK:
        logger.debug(
            "Token verification failed. Code= %d. Msg= %s",
            resp.status_code,
            resp.json(),
        )
        return False
    return True
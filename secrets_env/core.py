import logging
from http import HTTPStatus
from pathlib import Path
from typing import Dict, Optional, Tuple

import httpx

from secrets_env.auth import Auth
from secrets_env.exception import AuthenticationError, TypeError

logger = logging.getLogger(__name__)


class KVReader:
    """Read secrets from Vault KV engine."""

    def __init__(
        self,
        url: str,
        auth: Auth,
        ca_cert: Optional["Path"] = None,
        client_cert: Optional["Path"] = None,
        client_key: Optional["Path"] = None,
    ) -> None:
        """
        Parameters
        ----------
        url : str
            Vault URL.
        auth : Auth
            Authentication method and credentials.
        ca_cert : Path
            Path to server certificate.
        client_cert : Path
            Path to client side certificate file.
        client_key : Path
            Path to client key.
        """
        if not isinstance(url, str):
            raise TypeError("Expect str for url, got {}", type(url).__name__)
        if not isinstance(auth, Auth):
            raise TypeError(
                "Expect Auth instance for auth, got {}", type(auth).__name__
            )
        if ca_cert and not isinstance(ca_cert, Path):
            raise TypeError("Expect path for ca_cert, got {}", type(ca_cert).__name__)
        if client_cert and not isinstance(client_cert, Path):
            raise TypeError(
                "Expect path for client_cert, got {}", type(client_cert).__name__
            )
        if client_key and not isinstance(client_key, Path):
            raise TypeError(
                "Expect path for client_key, got {}", type(client_key).__name__
            )

        self.url = url
        self.auth = auth
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key

        self._client: Optional[httpx.Client] = None

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
        client = create_client(
            self.url, self.ca_cert, self.client_cert, self.client_key
        )

        # get token
        token = self.auth.login(client)
        if not token:
            raise AuthenticationError("Token is not populated")

        # verify token
        if is_authenticated(client, token):
            client.headers["X-Vault-Token"] = token
        else:
            raise AuthenticationError("Invalid token")

        self._client = client
        return client


def create_client(
    base_url: str,
    ca_cert: Optional["Path"],
    client_cert: Optional["Path"],
    client_key: Optional["Path"],
):
    """Initialize a client."""
    params = {
        "base_url": base_url,
    }

    if ca_cert:
        logger.debug("CA installed: %s", ca_cert)
        params["verify"] = str(ca_cert)
    if client_cert and client_key:
        logger.debug(
            "Client side certificate pair installed: %s, %s",
            client_cert,
            client_key,
        )
        params["cert"] = (str(client_cert), str(client_key))
    elif client_cert:
        logger.debug("Client side certificate file installed: %s", client_cert)
        params["cert"] = str(client_cert)

    return httpx.Client(**params)


def is_authenticated(client: httpx.Client, token: str):
    """Check is a token is authenticated.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/token
    """
    resp = client.request(
        "LIST", "/v1/auth/token/accessors", headers={"X-Vault-Token": token}
    )
    if resp.status_code != HTTPStatus.OK:
        logger.debug(
            "Token verification failed. Code= %d. Msg= %s",
            resp.status_code,
            resp.json(),
        )
        return False
    return True


def get_mount_point(client: httpx.Client, path: str) -> Tuple[str, int]:
    """Get mount point and KV engine version to a secret.

    Parameters
    ----------
    path : str
        Path to the secret

    Returns
    -------
    mount_point : str
        The path the secret engine mounted on.
    version : int
        The secret engine version

    See also
    --------
    Vault HTTP API
        https://developer.hashicorp.com/vault/api-docs/system/internal-ui-mounts
    consul-template
        https://github.com/hashicorp/consul-template/blob/v0.29.1/dependency/vault_common.go#L294-L357
    """
    try:
        resp = client.get(f"/v1/sys/internal/ui/mounts/{path}")
    except httpx.HTTPError as e:
        if not (reason := _reason_httpx_error(e)):
            raise
        logger.error("Error occurred during checking metadata for %s: %s", path, reason)
        return None, None

    if resp.status_code == HTTPStatus.OK:
        data = resp.json().get("data", {})

        mount_point = data.get("path")
        version = data.get("options", {}).get("version")

        if version == "2" and data.get("type") == "kv":
            return mount_point, 2
        elif version == "1":
            return mount_point, 1

        logging.error("Unknown version %s for path %s", version, path)
        logging.debug("Raw response: %s", resp)
        return None, None

    elif resp.status_code == HTTPStatus.NOT_FOUND:
        # 404 is expected on an older version of vault, default to version 1
        # https://github.com/hashicorp/consul-template/blob/v0.29.1/dependency/vault_common.go#L310-L311
        return "", 1

    logger.error("Error occurred during checking metadata for %s", path)
    _log_response(resp)
    return None, None


def _reason_httpx_error(e: httpx.HTTPError):
    logger.debug("Connection error occurs. Type= %s", type(e).__name__, exc_info=True)

    if isinstance(e, httpx.ProxyError):
        return "proxy error"
    elif isinstance(e, httpx.TransportError):
        return "connection error"

    return None


def _log_response(r: httpx.Response):
    try:
        code_enum = HTTPStatus(r.status_code)
        code_name = code_enum.name
    except ValueError:
        code_name = "unknown"

    logger.debug(
        "URL= %s. Status= %d (%s). Raw response= %s",
        r.url,
        r.status_code,
        code_name,
        r.text,
    )

import logging
import os
import re
from http import HTTPStatus
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        try:
            token = self.auth.login(client)
        except httpx.HTTPError as e:
            if not (reason := _reason_httpx_error(e)):
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

    def read_secret(self, path: str) -> Optional[Dict[str, str]]:
        """Read secret from Vault.

        Parameters
        ----------
        path : str
            Secret path

        Returns
        -------
        secret : dict
            Secret data. Or None when not found.
        """
        secret = read_secret(self.client, path)
        logger.debug(
            "Query for secret %s %s",
            path,
            "succeed" if secret is not None else "failed",
        )

        return secret

    def read_field(self, path: str, field: str) -> Optional[str]:
        """Read only one field from Vault.

        Parameters
        ----------
        path : str
            Secret path
        field : str
            Field name

        Returns
        -------
        value : str
            The secret value (if matched), or None when value not found.
        """
        if not isinstance(field, str):
            raise TypeError("Expect str for field, got {}", type(field).__name__)

        if not (secret := read_secret(self.client, path)):
            return None

        value = _get_field(secret, field)
        logger.debug(
            "Query for field %s#%s %s",
            path,
            field,
            "succeed" if value is not None else "failed",
        )

        return value

    def read_values(self, pairs: List[Tuple[str, str]]):
        """Get multiple secret values.

        Parameters
        ----------
        pairs : List[Tuple[str,str]]
            Pairs of secret path and field name.

        Returns
        -------
        values : Dict[Tuple[str,str], str]
            The secret values. The dictionary key is the given secret path and
            field name, and its value is the secret value. The value could be
            none on query error.
        """
        # read secrets
        secrets = {}
        for path, _ in pairs:
            if path in secrets:
                continue
            secrets[path] = read_secret(self.client, path)

        # extract values
        outputs = {}
        for path, field in pairs:
            secret = secrets[path]
            value = _get_field(secret, field)

            logger.debug(
                "Query for field %s#%s %s",
                path,
                field,
                "succeed" if value is not None else "failed",
            )

            outputs[path, field] = value

        return outputs


def create_client(
    base_url: str,
    ca_cert: Optional["Path"],
    client_cert: Optional["Path"],
    client_key: Optional["Path"],
):
    """Initialize a client."""
    if not isinstance(base_url, str):
        raise TypeError("Expect str for base_url, got {}", type(base_url).__name__)
    if ca_cert is not None and not isinstance(ca_cert, os.PathLike):
        raise TypeError("Expect path-like for ca_cert, got {}", type(ca_cert).__name__)
    if client_cert is not None and not isinstance(client_cert, os.PathLike):
        raise TypeError(
            "Expect path-like for client_cert, got {}", type(client_cert).__name__
        )
    if client_key is not None and not isinstance(client_key, os.PathLike):
        raise TypeError(
            "Expect path-like for client_key, got {}", type(client_key).__name__
        )

    logger.debug("Creating client to %s", base_url)

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


def get_mount_point(client: httpx.Client, path: str) -> Tuple[str, int]:
    """Get mount point and KV engine version to a secret.

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
    if not isinstance(client, httpx.Client):
        raise TypeError("Expect httpx.Client for client, got {}", type(client).__name__)
    if not isinstance(path, str):
        raise TypeError("Expect str for path, got {}", type(path).__name__)

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


def read_secret(client: httpx.Client, path: str) -> Optional[Dict[str, str]]:
    """Read secret from Vault.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/secret/kv
    """
    if not isinstance(client, httpx.Client):
        raise TypeError("Expect httpx.Client for client, got {}", type(client).__name__)
    if not isinstance(path, str):
        raise TypeError("Expect str for path, got {}", type(path).__name__)

    mount_point, version = get_mount_point(client, path)
    if not mount_point:
        return None

    logger.debug("Secret %s is mounted at %s (kv%d)", path, mount_point, version)

    if version == 1:
        url = f"/v1/{path}"
    elif version == 2:
        subpath = _remove_prefix(path, mount_point)
        url = f"/v1/{mount_point}data/{subpath}"

    try:
        resp = client.get(url)
    except httpx.HTTPError as e:
        if not (reason := _reason_httpx_error(e)):
            raise
        logger.error("Error occurred during query secret %s: %s", path, reason)
        return None

    if resp.status_code == HTTPStatus.OK:
        data = resp.json()
        if version == 1:
            return data["data"]
        elif version == 2:
            return data["data"]["data"]

    elif resp.status_code == HTTPStatus.NOT_FOUND:
        logger.error("Secret <data>%s</data> not found", path)
        return None

    logger.error("Error occurred during query secret %s", path)
    _log_response(resp)
    return None


def split_field(name: str) -> List[str]:
    """Split a field name into subsequences. By default, this function splits
    the name by dots, with supportting of preserving the quoted subpaths.
    """
    pattern_quoted = re.compile(r'"([^"]+)"')
    pattern_simple = re.compile(r"([\w-]+)")

    seq = []
    pos = 0
    while pos < len(name):
        # try match pattern
        if m := pattern_simple.match(name, pos):
            pass
        elif m := pattern_quoted.match(name, pos):
            pass
        else:
            break

        seq.append(m.group(1))

        # check remaining part
        # +1 for skipping the dot (if exists)
        pos = m.end() + 1

    if pos <= len(name):
        raise ValueError(f"Failed to parse name: {name}")

    return seq


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


def _remove_prefix(s: str, prefix: str) -> str:
    """Remove prefix if it exists."""
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


def _get_field(secret: dict, name: str) -> Optional[str]:
    """Traverse the secret data to get the field along with the given name."""
    for n in split_field(name):
        if not isinstance(secret, dict):
            return None
        secret = secret.get(n)

    if not isinstance(secret, str):
        return None

    return secret

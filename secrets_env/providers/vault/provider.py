import enum
import logging
import os
import re
import typing
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import httpx

from secrets_env.exceptions import (
    AuthenticationError,
    ConfigError,
    SecretNotFound,
    TypeError,
)
from secrets_env.provider import ProviderBase, RequestSpec
from secrets_env.utils import get_httpx_error_reason, log_httpx_response, removeprefix

if typing.TYPE_CHECKING:
    from secrets_env.providers.vault.auth.base import Auth
    from secrets_env.providers.vault.config import CertTypes

logger = logging.getLogger(__name__)


class Marker(enum.Enum):
    NoMatch = enum.auto()
    SecretNotExist = enum.auto()


class SecretSource(typing.NamedTuple):
    path: str
    field: str


KVVersion = Literal[1, 2]
VaultSecret = Dict[str, str]
VaultSecretQueryResult = Union[VaultSecret, Literal[Marker.SecretNotExist]]


class KvProvider(ProviderBase):
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
        self._secrets: Dict[str, VaultSecretQueryResult] = {}

    @property
    def type(self) -> str:
        return "vault"

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
        self._client = client

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

        return client

    def get(self, spec: RequestSpec) -> str:
        if not spec:
            raise ConfigError("Empty input")
        if isinstance(spec, str):
            # string input: path#key
            src = get_secret_source_str(spec)
        elif isinstance(spec, dict):
            # dict input: {"path": "foo", "key": "bar"}
            src = get_secret_source_dict(spec)
        else:
            raise TypeError("secret path spec", dict, spec)
        return self.read_field(src.path, src.field)

    def read_secret(self, path: str) -> VaultSecret:
        """Read secret from Vault.

        Parameters
        ----------
        path : str
            Secret path

        Returns
        -------
        secret : dict
            Secret data. Or 'SecretNotExist' marker when not found.
        """
        if not isinstance(path, str):
            raise TypeError("path", str, path)

        # try cache
        result = self._secrets.get(path, Marker.NoMatch)

        if result == Marker.NoMatch:
            # not found in cache - start query
            if secret := read_secret(self.client, path):
                result = secret
            else:
                result = Marker.SecretNotExist
            self._secrets[path] = result

        # return
        if result == Marker.SecretNotExist:
            raise SecretNotFound("Secret {} not found", path)
        return result

    def read_field(self, path: str, field: str) -> str:
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
            The secret value if matched
        """
        if not isinstance(field, str):
            raise TypeError("field", str, field)

        secret = self.read_secret(path)
        value = get_field(secret, field)

        if value is None:
            raise SecretNotFound("Secret {}#{} not found", path, field)
        return value


def create_client(
    base_url: str, ca_cert: Optional["Path"], client_cert: Optional["CertTypes"]
) -> httpx.Client:
    """Initialize a client."""
    if not isinstance(base_url, str):
        raise TypeError("base_url", str, base_url)
    if ca_cert is not None and not isinstance(ca_cert, os.PathLike):
        raise TypeError("ca_cert", "path-like", ca_cert)
    if client_cert is not None and not isinstance(client_cert, (os.PathLike, tuple)):
        raise TypeError("client_cert", "path-like", client_cert)

    logger.debug("Creating client to %s", base_url)

    params: dict[str, Any] = {"base_url": base_url}

    if ca_cert:
        logger.debug("CA installed: %s", ca_cert)
        params["verify"] = ca_cert
    if client_cert:
        logger.debug("Client side certificate file installed: %s", client_cert)
        params["cert"] = client_cert

    return httpx.Client(**params)


def is_authenticated(client: httpx.Client, token: str) -> bool:
    """Check is a token is authenticated.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/token
    """
    if not isinstance(client, httpx.Client):
        raise TypeError("client", "httpx client", client)
    if not isinstance(token, str):
        raise TypeError("token", str, token)

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


def get_mount_point(
    client: httpx.Client, path: str
) -> Tuple[Optional[str], Optional[KVVersion]]:
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
        raise TypeError("client", "httpx client", client)
    if not isinstance(path, str):
        raise TypeError("path", str, path)

    try:
        resp = client.get(f"/v1/sys/internal/ui/mounts/{path}")
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
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
    log_httpx_response(logger, resp)
    return None, None


def read_secret(client: httpx.Client, path: str) -> Optional[VaultSecret]:
    """Read secret from Vault.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/secret/kv
    """
    if not isinstance(client, httpx.Client):
        raise TypeError("client", "httpx client", client)
    if not isinstance(path, str):
        raise TypeError("path", str, path)

    mount_point, version = get_mount_point(client, path)
    if not mount_point:
        return None

    logger.debug("Secret %s is mounted at %s (kv%d)", path, mount_point, version)

    if version == 1:
        url = f"/v1/{path}"
    else:
        subpath = removeprefix(path, mount_point)
        url = f"/v1/{mount_point}data/{subpath}"

    try:
        resp = client.get(url)
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
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
    log_httpx_response(logger, resp)
    return None


def get_field(secret: dict, name: str) -> Optional[str]:
    """Traverse the secret data to get the field along with the given name."""
    for n in split_field(name):
        if not isinstance(secret, dict):
            return None
        secret = secret.get(n)  # type: ignore

    if not isinstance(secret, str):
        return None

    return secret


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


def get_secret_source_str(spec: str) -> SecretSource:
    idx = spec.find("#")
    if idx == -1:
        raise ConfigError("Missing delimiter '#'")
    elif idx == 0:
        raise ConfigError("Missing secret path part")
    elif idx == len(spec) - 1:
        raise ConfigError("Missing secret field part")

    path = spec[:idx]
    field = spec[idx + 1 :]
    return SecretSource(path, field)


def get_secret_source_dict(spec: dict) -> SecretSource:
    path = spec.get("path")
    if not path:
        raise ConfigError("Missing secret path part")
    elif not isinstance(path, str):
        raise TypeError("secret path", str, path)

    field = spec.get("field")
    if not field:
        raise ConfigError("Missing secret field part")
    elif not isinstance(field, str):
        raise TypeError("secret field", str, field)

    return SecretSource(path, field)

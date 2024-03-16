from __future__ import annotations

import enum
import logging
import re
import typing
from functools import cached_property
from http import HTTPStatus
from typing import Dict, Literal, Union

import httpx

import secrets_env.version
from secrets_env.exceptions import AuthenticationError, ConfigError, ValueNotFound
from secrets_env.provider import ProviderBase, RequestSpec
from secrets_env.utils import LruDict, get_httpx_error_reason, log_httpx_response

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from secrets_env.providers.vault.auth.base import Auth
    from secrets_env.providers.vault.config import CertTypes


logger = logging.getLogger(__name__)


class Marker(enum.Enum):
    NoMatch = enum.auto()
    SecretNotExist = enum.auto()


class SecretSource(typing.NamedTuple):
    path: str
    field: str


if typing.TYPE_CHECKING:
    KVVersion = Literal[1, 2]
    VaultSecret = Dict[str, str]
    VaultSecretQueryResult = Union[VaultSecret, Literal[Marker.SecretNotExist]]


class KvProvider(ProviderBase):
    """Read secrets from Vault KV engine."""

    def __init__(
        self,
        url: str,
        auth: Auth,
        *,
        proxy: str | None = None,
        ca_cert: Path | None = None,
        client_cert: CertTypes | None = None,
    ) -> None:
        self.url = url
        self.auth = auth
        self.proxy = proxy
        self.ca_cert = ca_cert
        self.client_cert = client_cert

        self._secrets: LruDict[str, VaultSecretQueryResult] = LruDict()

    @property
    def type(self) -> str:
        return "vault"

    @cached_property
    def client(self) -> httpx.Client:
        """Returns HTTP client."""
        logger.debug(
            "Vault client initialization requested. URL= %s, Auth type= %s",
            self.url,
            self.auth.method,
        )

        # initialize client
        client_params: dict[str, Any] = {"base_url": self.url}

        if self.proxy:
            logger.debug("Use proxy: %s", self.proxy)
            client_params["proxies"] = self.proxy
        if self.ca_cert:
            logger.debug("CA installed: %s", self.ca_cert)
            client_params["verify"] = self.ca_cert
        if self.client_cert:
            logger.debug("Client side certificate file installed: %s", self.client_cert)
            client_params["cert"] = self.client_cert

        client = httpx.Client(
            **client_params,
            headers={
                "Accept": "application/json",
                "User-Agent": (
                    f"secrets.env/{secrets_env.version.__version__} "
                    f"python-httpx/{httpx.__version__}"
                ),
            },
        )

        # install token
        client.headers["X-Vault-Token"] = get_token(client, self.auth)

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
            raise TypeError(
                f'Expected "spec" to match secret path spec, got {type(spec).__name__}'
            )
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
            raise TypeError(
                f'Expected "path" to be a string, got {type(path).__name__}'
            )

        # try cache
        result = self._secrets.get(path, Marker.NoMatch)

        if result == Marker.NoMatch:
            # not found in cache - start query
            if secret := read_secret(self.client, path):
                result = secret
            else:
                result = Marker.SecretNotExist
            self._secrets[path] = result

        # returns value
        if result == Marker.SecretNotExist:
            raise ValueNotFound("Secret {} not found", path)
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
            raise TypeError(
                f'Expected "field" to be a string, got {type(field).__name__}'
            )

        secret = self.read_secret(path)
        value = get_field(secret, field)

        if value is None:
            raise ValueNotFound("Secret {}#{} not found", path, field)
        return value


def get_token(client: httpx.Client, auth: Auth) -> str:
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
    if not isinstance(client, httpx.Client):
        raise TypeError(
            f'Expected "client" to be a httpx client, got {type(client).__name__}'
        )
    if not isinstance(token, str):
        raise TypeError(f'Expected "token" to be a string, got {type(token).__name__}')

    logger.debug("Validate token for %s", client.base_url)

    resp = client.get("/v1/auth/token/lookup-self", headers={"X-Vault-Token": token})
    if resp.is_success:
        return True

    logger.debug(
        "Token verification failed. Code= %d. Msg= %s",
        resp.status_code,
        resp.json(),
    )
    return False


def get_mount_point(
    client: httpx.Client, path: str
) -> tuple[str | None, KVVersion | None]:
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
        raise TypeError(
            f'Expected "client" to be a httpx client, got {type(client).__name__}'
        )
    if not isinstance(path, str):
        raise TypeError(f'Expected "path" to be a string, got {type(path).__name__}')

    try:
        resp = client.get(f"/v1/sys/internal/ui/mounts/{path}")
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
            raise
        logger.error("Error occurred during checking metadata for %s: %s", path, reason)
        return None, None

    if resp.is_success:
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


def read_secret(client: httpx.Client, path: str) -> VaultSecret | None:
    """Read secret from Vault.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/secret/kv
    """
    if not isinstance(client, httpx.Client):
        raise TypeError(
            f'Expected "client" to be a httpx client, got {type(client).__name__}'
        )
    if not isinstance(path, str):
        raise TypeError(f'Expected "path" to be a string, got {type(path).__name__}')

    mount_point, version = get_mount_point(client, path)
    if not mount_point:
        return None

    logger.debug("Secret %s is mounted at %s (kv%d)", path, mount_point, version)

    if version == 1:
        url = f"/v1/{path}"
    else:
        subpath = path.removeprefix(mount_point)
        url = f"/v1/{mount_point}data/{subpath}"

    try:
        resp = client.get(url)
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
            raise
        logger.error("Error occurred during query secret %s: %s", path, reason)
        return None

    if resp.is_success:
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


def get_field(secret: dict, name: str) -> str | None:
    """Traverse the secret data to get the field along with the given name."""
    for n in split_field(name):
        if not isinstance(secret, dict):
            return None
        secret = typing.cast(dict, secret.get(n))

    if not isinstance(secret, str):
        return None

    return secret


def split_field(name: str) -> list[str]:
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
        raise TypeError(f'Expected "path" to be a string, got {type(path).__name__}')

    field = spec.get("field")
    if not field:
        raise ConfigError("Missing secret field part")
    elif not isinstance(field, str):
        raise TypeError(f'Expected "field" to be a string, got {type(field).__name__}')

    return SecretSource(path, field)

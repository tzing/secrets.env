from __future__ import annotations

import enum
import logging
import typing
from functools import cached_property
from http import HTTPStatus
from typing import Literal

import httpx
from pydantic import (
    BaseModel,
    Field,
    InstanceOf,
    PrivateAttr,
    field_validator,
    model_validator,
    validate_call,
)
from pydantic_core import Url

import secrets_env.version
from secrets_env.exceptions import AuthenticationError
from secrets_env.provider import Provider
from secrets_env.providers.vault.config import VaultUserConfig
from secrets_env.utils import LruDict, get_httpx_error_reason, log_httpx_response

if typing.TYPE_CHECKING:
    from typing import Iterable, Iterator, Sequence

    from secrets_env.provider import Request
    from secrets_env.providers.vault.auth import Auth

logger = logging.getLogger(__name__)


class Marker(enum.Enum):
    """Internal marker for cache handling."""

    NoCache = enum.auto()
    NotFound = enum.auto()


class VaultPath(BaseModel):
    """Represents a path to a value in Vault."""

    path: str = Field(min_length=1)
    field: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.path}#{self.field_str}"

    @property
    def field_str(self) -> str:
        seq = []
        for f in self.field:
            if "." in f:
                seq.append(f'"{f}"')
            else:
                seq.append(f)
        return ".".join(seq)

    @model_validator(mode="before")
    @classmethod
    def _accept_shortcut(cls, data):
        if isinstance(data, dict):
            if data.get("value"):
                path = VaultPathSimplified.model_validate(data)
                return path.normalized()
        return data

    @field_validator("field", mode="before")
    @classmethod
    def _accept_str_for_field(cls, value) -> Iterable[str]:
        if isinstance(value, str):
            return _split_field_str(value)
        return value

    @field_validator("field", mode="after")
    @classmethod
    def _validate_field(cls, field: Sequence[str]) -> Sequence[str]:
        if not field:
            raise ValueError("Field cannot be empty")
        if any(not f for f in field):
            raise ValueError("Field cannot contain empty subpath")
        return field


class VaultPathSimplified(BaseModel):
    """Represents a simplified path to a value in Vault."""

    value: str

    @field_validator("value", mode="after")
    @classmethod
    def _check_value_format(cls, value: str) -> str:
        if value.count("#") != 1:
            raise ValueError("Invalid format. Expected 'path#field'.")
        return value

    def normalized(self) -> dict:
        path, field = self.value.rsplit("#", 1)
        return {
            "path": path,
            "field": field,
        }


def _split_field_str(f: str) -> Iterator[str]:
    """Split a field name into subsequences. By default, this function splits
    the name by dots, with supportting of preserving the quoted subpaths.
    """
    pos = 0
    while pos < len(f):
        if f[pos] == '"':
            # quoted
            end = f.find('"', pos + 1)
            if end == -1:
                raise ValueError(f"Failed to parse field: {f}")
            yield f[pos + 1 : end]
            pos = end + 2
        else:
            # simple
            end = f.find(".", pos)
            if end == -1:
                end = len(f)
            yield f[pos:end]
            pos = end + 1


class VaultKvProvider(Provider, VaultUserConfig):
    """Read secrets from Hashicorp Vault KV engine."""

    type = "vault"

    _cache: dict[str, dict | Marker] = PrivateAttr(default_factory=LruDict)

    @cached_property
    def client(self) -> httpx.Client:
        """Returns HTTP client.

        Raises
        ------
        AuthenticationError
            If the token cannot be retrieved or is invalid.
        UnsupportedError
            If the operation is unsupported.
        """
        logger.debug("Vault client initialization requested. URL= %s", self.url)

        if self.teleport:
            logger.debug("Teleport configuration is set. Use it for connecting Vault.")

            param = self.teleport.connection_param
            logger.debug(f"Teleport connection parameter: {param!r}")

            self.teleport = None
            self.url = Url(param.uri)
            self.tls.ca_cert = param.path_ca
            self.tls.client_cert = param.path_cert
            self.tls.client_key = param.path_key

        client = create_http_client(self)
        client.headers["X-Vault-Token"] = get_token(client, self.auth)

        return client

    def _get_value_(self, spec: Request) -> str:
        path = VaultPath.model_validate(spec.model_dump(exclude_none=True))
        secret = self._read_secret(path)

        for f in path.field:
            try:
                secret = secret[f]
            except (KeyError, TypeError):
                raise LookupError(
                    f'Field "{path.field_str}" not found in "{path.path}"'
                ) from None

        if not isinstance(secret, str):
            raise LookupError(
                f'Field "{path.field_str}" in "{path.path}" is not point to a string value'
            )

        return secret

    def _read_secret(self, path: VaultPath) -> dict:
        """
        Get a secret from the Vault. A Vault "secret" is a object that contains
        key-value pairs.

        This method wraps the `read_secret` method and cache the result.

        Raises
        ------
        LookupError
            If the secret is not found.
        """
        result = self._cache.get(path.path, Marker.NoCache)

        if result == Marker.NoCache:
            result = read_secret(self.client, path.path)
            if result is None:
                result = Marker.NotFound
            self._cache[path.path] = result

        if result == Marker.NotFound:
            raise LookupError(f'Secret "{path}" not found')

        return result


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


def get_token(client: InstanceOf[httpx.Client], auth: Auth) -> str:
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
        raise AuthenticationError(f"Encounter {reason} while retrieving token") from e

    # verify
    if not is_authenticated(client, token):
        raise AuthenticationError("Invalid token")

    return token


@validate_call
def is_authenticated(client: InstanceOf[httpx.Client], token: str) -> bool:
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


@validate_call
def read_secret(client: InstanceOf[httpx.Client], path: str) -> dict | None:
    """Read secret from Vault.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/secret/kv
    """
    mount = get_mount(client, path)
    if not mount:
        return

    logger.debug("Secret %s is mounted at %s (kv%d)", path, mount.path, mount.version)

    if mount.version == 2:
        subpath = path.removeprefix(mount.path)
        request_path = f"/v1/{mount.path}data/{subpath}"
    else:
        request_path = f"/v1/{path}"

    try:
        resp = client.get(request_path)
    except httpx.HTTPError as e:
        if not (reason := get_httpx_error_reason(e)):
            raise
        logger.error("Error occurred during query secret %s: %s", path, reason)
        return

    if resp.is_success:
        data = resp.json()
        if mount.version == 2:
            return data["data"]["data"]
        else:
            return data["data"]

    elif resp.status_code == HTTPStatus.NOT_FOUND:
        logger.error("Secret <data>%s</data> not found", path)
        return

    logger.error("Error occurred during query secret %s", path)
    log_httpx_response(logger, resp)
    return


class _RawMountMetadata(BaseModel):
    """
    {
        "data": {
            "options": {"version": "1"},
            "path": "secrets/",
            "type": "kv",
        }
    }
    """

    data: _DataBlock

    class _DataBlock(BaseModel):

        options: _OptionBlock
        path: str
        type: str

        class _OptionBlock(BaseModel):
            version: str


class MountMetadata(BaseModel):
    """Represents a mount point and KV engine version to a secret."""

    path: str
    version: Literal[1, 2]


@validate_call
def get_mount(client: InstanceOf[httpx.Client], path: str) -> MountMetadata | None:
    """Get mount point and KV engine version to a secret.

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
        if not (reason := get_httpx_error_reason(e)):
            raise
        logger.error("Error occurred during checking metadata for %s: %s", path, reason)
        return

    if resp.is_success:
        parsed = _RawMountMetadata.model_validate_json(resp.read())
        return MountMetadata(
            path=parsed.data.path,
            version=int(parsed.data.options.version),  # type: ignore[reportArgumentType]
        )

    elif resp.status_code == HTTPStatus.NOT_FOUND:
        # 404 is expected on an older version of vault, default to version 1
        # https://github.com/hashicorp/consul-template/blob/v0.29.1/dependency/vault_common.go#L310-L311
        return MountMetadata(path="", version=1)

    logger.error("Error occurred during checking metadata for %s", path)
    log_httpx_response(logger, resp)
    return

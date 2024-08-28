from __future__ import annotations

import enum
import logging
import os
import typing
from functools import cached_property
from pathlib import Path

import httpx
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator
from pydantic_core import Url

import secrets_env.version
from secrets_env.exceptions import AuthenticationError
from secrets_env.provider import Provider
from secrets_env.providers.vault.api import is_authenticated, read_secret
from secrets_env.providers.vault.config import TlsConfig, VaultUserConfig
from secrets_env.utils import LruDict, get_httpx_error_reason

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

        # load url & tls from teleport
        if self.teleport:
            logger.debug("Teleport configuration is set. Use it for connecting Vault.")

            param = self.teleport.connection_param
            logger.debug(f"Teleport connection parameter: {param!r}")

            self.teleport = None
            self.url = Url(param.uri)
            self.tls = TlsConfig()
            self.tls.ca_cert = param.path_ca
            self.tls.client_cert = param.path_cert
            self.tls.client_key = param.path_key

        # initialize client
        client = create_http_client(self)

        # get token
        if token := get_token_from_helper(client):
            client.headers["X-Vault-Token"] = token
        elif token := get_token(client, self.auth_object):
            save_token_to_helper(token)
            client.headers["X-Vault-Token"] = token

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
            raise LookupError(f"Failed to load secret `{path}`")

        return result


def create_http_client(config: VaultUserConfig) -> httpx.Client:
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
        raise AuthenticationError(f"Encounter {reason} while retrieving token") from e

    # verify
    if not is_authenticated(client, token):
        raise AuthenticationError("Invalid token")

    return token


def get_token_from_helper(client: httpx.Client) -> str | None:
    """
    Get token from token helper.

    See also
    --------
    https://www.vaultproject.io/docs/commands/token-helper
    """
    logger.debug("Attempting to use token helper")

    token_helper = get_token_helper_path()
    if not token_helper.is_file():
        logger.debug("Token helper not found")
        return None

    token = token_helper.read_text()
    if is_authenticated(client, token):
        logger.debug("Token helper is valid")
        return token

    logger.debug("Token helper is invalid")
    return None


def save_token_to_helper(token: str) -> None:
    """Save token to token helper."""
    if os.getuid() == 0 or os.geteuid() == 0 or os.getgid() == 0:
        logger.debug("Skip saving token to token helper for root user")
        return

    token_helper = get_token_helper_path()

    try:
        token_helper.write_text(token)
        logger.debug("Token saved to token helper: %s", token_helper)
    except Exception:
        logger.debug("Failed to write token to token helper", exc_info=True)


def get_token_helper_path() -> Path:
    """Get path to the token helper file."""
    return Path.home() / ".vault-token"

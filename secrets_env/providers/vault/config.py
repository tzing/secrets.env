from __future__ import annotations

import logging
import typing
from functools import cached_property
from typing import TypedDict

from pydantic import (
    BaseModel,
    Field,
    FilePath,
    HttpUrl,
    ValidationError,
    field_validator,
    model_validator,
)

from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.utils import get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

    from secrets_env.providers.vault.auth.base import Auth

    CertTypes = Path | tuple[Path, Path]

DEFAULT_AUTH_METHOD = "token"


logger = logging.getLogger(__name__)


class TlsConfig(BaseModel):
    ca_cert: FilePath | None = None
    client_cert: FilePath | None = None
    client_key: FilePath | None = None

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values: Self | dict) -> Self | dict:
        if isinstance(values, dict):
            if ca_cert := get_env_var(
                "SECRETS_ENV_CA_CERT",
                "VAULT_CACERT",
            ):
                values["ca_cert"] = ca_cert
            if client_cert := get_env_var(
                "SECRETS_ENV_CLIENT_CERT",
                "VAULT_CLIENT_CERT",
            ):
                values["client_cert"] = client_cert
            if client_key := get_env_var(
                "SECRETS_ENV_CLIENT_KEY",
                "VAULT_CLIENT_KEY",
            ):
                values["client_key"] = client_key
        return values

    @model_validator(mode="after")
    def _require_client_cert(self) -> Self:
        if self.client_key and not self.client_cert:
            raise ValueError("client_cert is required when client_key is provided")
        return self


class VaultUserConfig(BaseModel):
    url: HttpUrl
    auth_config: dict[str, str] = Field(alias="auth")
    proxy: HttpUrl | None = None
    tls: TlsConfig = Field(default_factory=TlsConfig)

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values: Self | dict) -> Self | dict:
        if isinstance(values, dict):
            if url := get_env_var(
                "SECRETS_ENV_ADDR",
                "VAULT_ADDR",
            ):
                values["url"] = url
            if proxy := get_env_var(
                "SECRETS_ENV_PROXY",
                "VAULT_PROXY_ADDR",
                "VAULT_HTTP_PROXY",
            ):
                values["proxy"] = proxy
        return values

    @model_validator(mode="before")
    @classmethod
    def _setdefault_auth(cls, values: Self | dict) -> Self | dict:
        if isinstance(values, dict):
            if not values.get("auth"):
                values["auth"] = {"method": DEFAULT_AUTH_METHOD}
                logger.warning(
                    "Missing required config <mark>auth method</mark>. "
                    "Use default method <data>%s</data>",
                    DEFAULT_AUTH_METHOD,
                )
        return values

    @field_validator("auth_config", mode="before")
    @classmethod
    def _validate_auth(cls, value: dict | str) -> dict:
        if isinstance(value, str):
            # syntax sugar: `auth: <method>`
            return {"method": value}
        elif isinstance(value, dict):
            if "method" not in value:
                raise ValueError("Missing required config <mark>auth method</mark>")
        return value

    @cached_property
    def auth(self) -> Auth:
        """Create auth instance from auth config.

        Raises
        ------
        ValueError
            If auth method is not supported.
        ValidationError
            If auth config is invalid.
        """
        return create_auth_by_name(self.url, self.auth_config)

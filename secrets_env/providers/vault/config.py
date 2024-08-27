from __future__ import annotations

import enum
import logging
import typing
import warnings
from functools import cached_property
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    FilePath,
    HttpUrl,
    field_validator,
    model_validator,
)

from secrets_env.providers.teleport import TeleportUserConfig  # noqa: TCH001
from secrets_env.providers.vault.auth import create_auth
from secrets_env.utils import get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path

    from pydantic_core.core_schema import ValidationInfo, ValidatorFunctionWrapHandler

    from secrets_env.providers.vault.auth.base import Auth

    CertTypes = Path | tuple[Path, Path]

DEFAULT_AUTH_METHOD = "token"


logger = logging.getLogger(__name__)


class LazyProvidedMarker(enum.Enum):
    """Internal marker for values that would be provided later."""

    ProvidedByTeleport = enum.auto()


class TlsConfig(BaseModel):
    ca_cert: FilePath | None = None
    client_cert: FilePath | None = None
    client_key: FilePath | None = None

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values):
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
    def _require_client_cert(self):
        if self.client_key and not self.client_cert:
            raise ValueError("client_cert is required when client_key is provided")
        return self

    def __bool__(self) -> bool:
        return bool(self.ca_cert or self.client_cert or self.client_key)


class AuthConfig(BaseModel):
    """
    Configuration for authentication method.

    This class is used to validate the input type for the ``auth`` field in
    Vault configuration. It will be converted to the corresponding
    :class:`Authenticator` instance by the Vault configuration parser.
    """

    method: Annotated[str, AfterValidator(str.lower)]
    role: str | None = None
    username: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        # accept string as method
        if isinstance(values, str):
            values = {"method": values}

        # get role
        if role := get_env_var("SECRETS_ENV_ROLE"):
            logger.debug("Found role from environment variable: %s", role)
            values["role"] = role

        # get username
        if username := get_env_var("SECRETS_ENV_USERNAME"):
            logger.debug("Found username from environment variable.")
            values["username"] = username

        return values


class VaultUserConfig(BaseModel):
    url: HttpUrl
    auth: AuthConfig
    proxy: HttpUrl | None = None
    tls: TlsConfig = Field(default_factory=TlsConfig)
    teleport: TeleportUserConfig | None = None

    @model_validator(mode="before")
    @classmethod
    def _before_validator(cls, values):
        if isinstance(values, dict):
            # read field value from env vars
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

            # set default auth value
            if not values.get("auth"):
                values["auth"] = {"method": DEFAULT_AUTH_METHOD}
                _warn(
                    "Missing required config <mark>auth method</mark>. "
                    f"Use default method <data>{DEFAULT_AUTH_METHOD}</data>."
                )

            # overrides related fields when teleport is set
            if values.get("teleport"):
                if values.get("url"):
                    _warn(
                        "Any provided URL would be discarded when 'teleport' config is set"
                    )
                if values.get("tls"):
                    _warn(
                        "TLS configuration would be overlooked when 'teleport' config is set"
                    )
                values["url"] = LazyProvidedMarker.ProvidedByTeleport
                values["tls"] = LazyProvidedMarker.ProvidedByTeleport

        return values

    @field_validator("url", "tls", mode="wrap")
    @classmethod
    def _bypass_marker(
        cls, value, validator: ValidatorFunctionWrapHandler, info: ValidationInfo
    ) -> HttpUrl | LazyProvidedMarker:
        if isinstance(value, LazyProvidedMarker):
            return value
        return validator(value)

    @cached_property
    def auth_object(self) -> Auth:
        """Create auth instance from auth config.

        Raises
        ------
        ValueError
            If auth method is not supported.
        ValidationError
            If auth config is invalid.
        """
        if isinstance(self.url, LazyProvidedMarker):
            raise RuntimeError("Vault URL is not loaded yet")
        return create_auth(
            url=self.url,
            method=self.auth.method,
            role=self.auth.role,
            username=self.auth.username,
        )


def _warn(s: str):
    warnings.warn(s, UserWarning, stacklevel=2)

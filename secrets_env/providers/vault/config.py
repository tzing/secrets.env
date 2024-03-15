from __future__ import annotations

import logging
import typing
from typing import TypedDict

from pydantic import (
    BaseModel,
    FilePath,
    HttpUrl,
    ValidationError,
    field_validator,
    model_validator,
)

from secrets_env.exceptions import ConfigError
from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.utils import ensure_dict, ensure_str, get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Self

    from secrets_env.providers.vault.auth.base import Auth

    CertTypes = Path | tuple[Path, Path]

DEFAULT_AUTH_METHOD = "token"


logger = logging.getLogger(__name__)


class RawVaultUserConfig(BaseModel):
    url: HttpUrl
    auth: dict[str, str]
    proxy: HttpUrl | None = None
    tls: TlsConfig | None = None

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
    def _process_auth(cls, values: Self | dict) -> Self | dict:
        if isinstance(values, dict):
            # prepare auth config
            if val := values.get("auth"):
                # has `auth` key
                if isinstance(val, str):
                    # syntax sugar: `auth: <method>`
                    values["auth"] = {"method": val}
            else:
                # missing `auth` key; show warning and use default method
                logger.warning(
                    "Missing required config <mark>auth method</mark>. "
                    "Use default method <data>%s</data>",
                    DEFAULT_AUTH_METHOD,
                )
                values["auth"] = {"method": DEFAULT_AUTH_METHOD}
        return values

    @field_validator("auth")
    def _validate_auth(cls, auth: dict) -> dict:
        if "method" not in auth:
            raise ValueError("Missing required config <mark>auth method</mark>")
        return auth


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


class VaultConnectionInfo(TypedDict):
    url: str
    auth: Auth
    proxy: str

    # tls
    ca_cert: Path
    client_cert: CertTypes


def get_connection_info(data: dict) -> VaultConnectionInfo | None:
    try:
        parsed = RawVaultUserConfig.model_validate(data)
    except (ValidationError, TypeError):
        return

    auth = get_auth(str(parsed.url), parsed.auth)
    if not auth:
        return

    conn_info = VaultConnectionInfo(
        url=str(parsed.url),
        auth=auth,
    )

    if parsed.proxy:
        conn_info["proxy"] = str(parsed.proxy)
    if parsed.tls:
        if parsed.tls.ca_cert:
            conn_info["ca_cert"] = parsed.tls.ca_cert
        if parsed.tls.client_key:
            conn_info["client_cert"] = (parsed.tls.client_cert, parsed.tls.client_key)
        elif parsed.tls.client_cert:
            conn_info["client_cert"] = parsed.tls.client_cert

    return conn_info


def get_auth(url: str, data: dict) -> Auth | None:
    # syntax sugar: `auth: <method>`
    if isinstance(data, str):
        data = {"method": data}

    # type check
    data, _ = ensure_dict("source.auth", data)

    # set auth method
    if "method" not in data:
        data["method"] = DEFAULT_AUTH_METHOD
        logger.warning(
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>%s</data>",
            DEFAULT_AUTH_METHOD,
        )

    _, ok = ensure_str("auth method", data["method"])
    if not ok:
        return None

    try:
        return create_auth_by_name(url, data)
    except ConfigError:
        logger.error("Unknown auth method: <data>%s</data>", data["method"])
        return None

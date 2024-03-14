from __future__ import annotations

import logging
import typing
from typing import TypedDict

from pydantic import BaseModel, FilePath, ValidationError, model_validator

from secrets_env.exceptions import ConfigError
from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.utils import ensure_dict, ensure_str, get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, Self

    from secrets_env.providers.vault.auth.base import Auth

    CertTypes = Path | tuple[Path, Path]

DEFAULT_AUTH_METHOD = "token"


class TlsConfig(BaseModel):
    ca_cert: FilePath | None = None
    client_cert: FilePath | None = None
    client_key: FilePath | None = None

    @model_validator(mode="before")
    @classmethod
    def _use_env_var(cls, values):
        assert isinstance(values, dict)
        if ca_cert := get_env_var("SECRETS_ENV_CA_CERT", "VAULT_CACERT"):
            values["ca_cert"] = ca_cert
        if client_cert := get_env_var("SECRETS_ENV_CLIENT_CERT", "VAULT_CLIENT_CERT"):
            values["client_cert"] = client_cert
        if client_key := get_env_var("SECRETS_ENV_CLIENT_KEY", "VAULT_CLIENT_KEY"):
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


logger = logging.getLogger(__name__)


def get_connection_info(data: dict) -> VaultConnectionInfo | None:
    output: dict[str, Any] = {}
    is_success = True

    # url
    output["url"] = url = get_url(data)
    if not url:
        return None

    # auth
    if auth := get_auth(url, data.get("auth", {})):
        output["auth"] = auth
    else:
        is_success = False

    # proxy
    proxy, ok = get_proxy(data)
    is_success &= ok
    if ok and proxy:
        output["proxy"] = proxy

    # tls
    try:
        model_tls = TlsConfig.model_validate(data.get("tls", {}))

        if model_tls.ca_cert:
            output["ca_cert"] = model_tls.ca_cert

        if model_tls.client_key:
            output["client_cert"] = (model_tls.client_cert, model_tls.client_key)
        elif model_tls.client_cert:
            output["client_cert"] = model_tls.client_cert

    except (ValidationError, TypeError):
        is_success = False

    return typing.cast(VaultConnectionInfo, output) if is_success else None


def get_url(data: dict) -> str | None:
    url = get_env_var("SECRETS_ENV_ADDR", "VAULT_ADDR")
    if not url:
        url = data.get("url", None)

    if not url:
        logger.error(
            "Missing required config <mark>url</mark>. "
            "Please provide from config file (<mark>source.url</mark>) "
            "or environment variable (<mark>SECRETS_ENV_ADDR</mark>)."
        )
        return None

    url, ok = ensure_str("source.url", url)
    if not ok:
        return None

    return url


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


def get_proxy(data: dict) -> tuple[str | None, bool]:
    # (1) Vault prioritized `VAULT_PROXY_ADDR` before `VAULT_HTTP_PROXY`
    #     https://developer.hashicorp.com/vault/docs/commands#environment-variables
    # (2) Standard proxy variables are later captured by httpx
    proxy = get_env_var("SECRETS_ENV_PROXY", "VAULT_PROXY_ADDR", "VAULT_HTTP_PROXY")
    if not proxy:
        proxy = data.get("proxy")
    if not proxy:
        return None, True

    proxy, ok = ensure_str("source.proxy", proxy)
    if not ok or not proxy:
        return None, False

    if not proxy.lower().startswith(("http://", "https://")):
        logger.warning("Proxy must specify 'http://' or 'https://' protocol")
        return None, False

    return proxy, True

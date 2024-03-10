from __future__ import annotations

import logging
import typing
from typing import TypedDict

from secrets_env.exceptions import ConfigError
from secrets_env.providers.vault.auth import create_auth_by_name
from secrets_env.utils import ensure_dict, ensure_path, ensure_str, get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

    from secrets_env.providers.vault.auth.base import Auth

    CertTypes = Path | tuple[Path, Path]

DEFAULT_AUTH_METHOD = "token"


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
    data_tls = data.get("tls", {})

    ca_cert, ok = get_tls_ca_cert(data_tls)
    is_success &= ok
    if ok and ca_cert:
        output["ca_cert"] = ca_cert

    client_cert, ok = get_tls_client_cert(data_tls)
    is_success &= ok
    if ok and client_cert:
        output["client_cert"] = client_cert

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


def get_tls_ca_cert(data: dict) -> tuple[Path | None, bool]:
    path = get_env_var("SECRETS_ENV_CA_CERT", "VAULT_CACERT")
    if not path:
        path = data.get("ca_cert")

    if path:
        return ensure_path("TLS server certificate (CA cert)", path)

    return None, True


def get_tls_client_cert(data: dict) -> tuple[CertTypes | None, bool]:
    client_cert, client_key = None, None
    is_success = True

    # certificate
    path = get_env_var("SECRETS_ENV_CLIENT_CERT", "VAULT_CLIENT_CERT")
    if not path:
        path = data.get("client_cert")

    if path:
        client_cert, ok = ensure_path("TLS client-side certificate (client_cert)", path)
        is_success &= ok

    # private key
    path = get_env_var("SECRETS_ENV_CLIENT_KEY", "VAULT_CLIENT_KEY")
    if not path:
        path = data.get("client_key")

    if path:
        client_key, ok = ensure_path("TLS private key (client_key)", path)
        is_success &= ok

    # build output
    if not is_success:
        return None, False

    if client_cert and client_key:
        return (client_cert, client_key), True
    elif client_cert:
        return client_cert, True
    elif client_key:
        logger.error(
            "Missing config <mark>client_cert</mark>. "
            "Please provide from config file (<mark>source.tls.client_cert</mark>) "
            "or environment variable (<mark>SECRETS_ENV_CLIENT_CERT</mark>)."
        )
        return None, False

    return None, True

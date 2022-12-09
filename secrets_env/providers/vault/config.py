import importlib
import logging
import typing
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

from secrets_env.io import get_env_var
from secrets_env.utils import ensure_dict, ensure_path, ensure_str

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.providers.vault.auth.base import Auth

DEFAULT_AUTH_METHOD = "token"

AUTH_METHODS = {
    "basic": ("secrets_env.providers.vault.auth.userpass", "BasicAuth"),
    "ldap": ("secrets_env.providers.vault.auth.userpass", "LDAPAuth"),
    "null": ("secrets_env.providers.vault.auth.null", "NoAuth"),
    "oidc": ("secrets_env.providers.vault.auth.oidc", "OpenIDConnectAuth"),
    "okta": ("secrets_env.providers.vault.auth.userpass", "OktaAuth"),
    "radius": ("secrets_env.providers.vault.auth.userpass", "RADIUSAuth"),
    "token": ("secrets_env.providers.vault.auth.token", "TokenAuth"),
}

CertTypes = Union[
    # cert file
    "Path",
    # client file, key file
    Tuple["Path", "Path"],
]


class VaultConnectionInfo(TypedDict):
    url: str
    auth: "Auth"

    # tls
    ca_cert: "Path"
    client_cert: CertTypes


logger = logging.getLogger(__name__)


def get_connection_info(data: dict) -> Optional[VaultConnectionInfo]:
    output: Dict[str, Any] = {}
    is_success = True

    # url
    if url := get_url(data):
        output["url"] = url
    else:
        is_success = False

    # auth
    if auth := get_auth(data.get("auth", {})):
        output["auth"] = auth
    else:
        is_success = False

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


def get_url(data: dict) -> Optional[str]:
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


def get_auth(data: dict) -> Optional["Auth"]:
    # syntax sugar: `auth: <method>`
    if isinstance(data, str):
        data = {"method": data}

    # type check
    data, _ = ensure_dict("source.auth", data)

    # extract auth method
    method = get_env_var("SECRETS_ENV_METHOD")
    if not method:
        method = data.get("method")

    if not method:
        method = DEFAULT_AUTH_METHOD
        logger.warning(
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>%s</data>",
            DEFAULT_AUTH_METHOD,
        )

    method, _ = ensure_str("auth method", method)
    if not method:
        return None

    # get auth class (import by name)
    module_name, class_name = AUTH_METHODS.get(method.lower(), (None, None))
    if not module_name or not class_name:
        logger.error("Unknown auth method: <data>%s</data>", method)
        return None

    module = importlib.import_module(module_name)
    class_: "Auth" = getattr(module, class_name)

    # build auth object from data
    return class_.load(data)


def get_tls_ca_cert(data: dict) -> Tuple[Optional["Path"], bool]:
    path = get_env_var("SECRETS_ENV_CA_CERT", "VAULT_CACERT")
    if not path:
        path = data.get("ca_cert")

    if path:
        return ensure_path("TLS server certificate (CA cert)", path)

    return None, True


def get_tls_client_cert(data: dict) -> Tuple[Optional[CertTypes], bool]:
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

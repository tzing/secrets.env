import logging
import typing
from typing import Any, Dict, NamedTuple, Optional, Tuple, TypedDict, Union

import secrets_env.auth
from secrets_env.config.typing import ensure_dict, ensure_path, ensure_str
from secrets_env.io import get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.auth import Auth

DEFAULT_AUTH_METHOD = "token"

logger = logging.getLogger(__name__)

CertTypes = Union[
    # cert file
    "Path",
    # client file, key file
    Tuple["Path", "Path"],
]


class ClientConfig(TypedDict):
    url: str
    auth: "Auth"

    # tls
    ca_cert: "Path"
    client_cert: CertTypes


class SecretSource(NamedTuple):
    path: str
    field: str


SecretMapping = Dict[str, SecretSource]


class Config(TypedDict):
    client: ClientConfig
    secrets: SecretMapping


def parse_config(data: dict) -> Config:
    """Parse and validate configs, build it into structured object."""
    is_success = True
    output = {}

    # `source` section
    section_source = data.get("source", {})
    section_source, ok = ensure_dict("source", section_source)
    is_success &= ok

    # `secrets` section
    section_secrets = data.get("secrets", {})
    section_secrets, ok = ensure_dict("secrets", section_secrets)
    is_success &= ok

    raise NotImplementedError()


def parse_section_source(data: dict) -> Optional[ClientConfig]:
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
    if ca_cert := get_tls_ca_cert(data):
        output["ca_cert"] = ca_cert

    client_cert, ok = get_tls_client_cert(data)
    is_success &= ok
    if ok:
        output["client_cert"] = client_cert

    return output if is_success else None  # pyright: ignore[reportGeneralTypeIssues]


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

    return secrets_env.auth.get_auth(method, data)


def get_tls_ca_cert(data: dict) -> Optional["Path"]:
    path = get_env_var("SECRETS_ENV_CA_CERT", "VAULT_CACERT")
    if not path:
        path = data.get("ca_cert")

    if path:
        ca_cert, _ = ensure_path("TLS server certificate (CA cert)", path)
        return ca_cert

    return None


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
            "Please provide from config file (<mark>source.url</mark>) "
            "or environment variable (<mark>SECRETS_ENV_ADDR</mark>)."
        )
        return None, False

    return None, True

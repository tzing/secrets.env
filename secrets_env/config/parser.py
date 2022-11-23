import logging
import re
import typing
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

import secrets_env.auth
from secrets_env.config.types import ensure_dict, ensure_path, ensure_str
from secrets_env.io import get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.auth import Auth

DEFAULT_AUTH_METHOD = "token"

logger = logging.getLogger(__name__)

__regex_var_name = None

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


class SecretSource(typing.NamedTuple):
    path: str
    field: str


SecretMapping = Dict[str, SecretSource]


class Config(TypedDict):
    client: ClientConfig
    secrets: SecretMapping


def parse_config(data: dict) -> Optional[Config]:
    """Parse and validate configs, build it into structured object."""
    # stop parse config when there's no target
    if not data.get("secrets"):
        logger.debug("No target specificied.")
        return None

    is_success = True

    # `source` section
    data_source = data.get("source", {})
    data_source, ok = ensure_dict("source", data_source)
    is_success &= ok

    if not (config_source := parse_section_source(data_source)):
        is_success = False

    # `secrets` section
    data_secrets = data.get("secrets", {})
    data_secrets, ok = ensure_dict("secrets", data_secrets)
    is_success &= ok

    if not (config_secrets := parse_section_secret(data_secrets)):
        is_success = False

    # output
    if not is_success:
        return None

    return {
        "client": config_source,
        "secrets": config_secrets,
    }  # pyright: ignore[reportGeneralTypeIssues]


def parse_section_source(data: dict) -> Optional[Dict[str, Any]]:
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

    return output if is_success else None


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


def parse_section_secret(data: Dict[str, Union[str, Dict[str, str]]]) -> SecretMapping:
    global __regex_var_name
    if not __regex_var_name:
        __regex_var_name = re.compile(
            r"[a-z_][a-z0-9_]*", re.RegexFlag.ASCII | re.RegexFlag.IGNORECASE
        )

    secrets = {}
    for name, path_spec in data.items():
        if not __regex_var_name.fullmatch(name):
            logger.warning(
                "Invalid environment variable name <data>%s</data>. "
                "Skipping this variable.",
                name,
            )
            continue

        if src := get_secret_source(name, path_spec):
            secrets[name] = src

    return secrets


def get_secret_source(
    name: str, path_spec: Union[str, Dict[str, str]]
) -> Optional[SecretSource]:
    if not path_spec:
        err_msg = "Empty input"

    elif isinstance(path_spec, str):
        # string input: path#key
        src, err_msg = get_secret_source_str(path_spec)
        if src:
            return src

    elif isinstance(path_spec, dict):
        # dict input: {"path": "foo", "key": "bar"}
        src, err_msg = get_secret_source_dict(path_spec)
        if src:
            return src

    else:
        err_msg = "Invalid type"

    logger.warning(
        "Target secret <data>%s</data> is invalid. %s. Discard this variable.",
        name,
        err_msg,
    )

    return None


def get_secret_source_str(spec: str) -> Tuple[Optional[SecretSource], Optional[str]]:
    idx = spec.find("#")
    if idx == -1:
        return None, "Missing delimiter '#'"
    elif idx == 0:
        return None, "Missing secret path"
    elif idx == len(spec) - 1:
        return None, "Missing secret field"

    path = spec[:idx]
    field = spec[idx + 1 :]
    return SecretSource(path, field), None


def get_secret_source_dict(spec: dict) -> Tuple[Optional[SecretSource], Optional[str]]:
    path = spec.get("path")
    if not path:
        return None, "Missing secret path"
    elif not isinstance(path, str):
        return None, "Invalid type of path"

    field = spec.get("field")
    if not field:
        return None, "Missing secret field"
    elif not isinstance(field, str):
        return None, "Invalid type of field"

    return SecretSource(path, field), None

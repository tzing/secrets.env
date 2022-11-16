import logging
import typing
from typing import Dict, NamedTuple, Optional, TypedDict

import secrets_env.auth
from secrets_env.config.typing import ensure_dict, ensure_path, ensure_str
from secrets_env.io import get_env_var

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.auth import Auth

logger = logging.getLogger(__name__)


class ClientConfig(TypedDict):
    url: str
    auth: "Auth"
    ca_cert: "Path"
    client_cert: "Path"
    client_key: "Path"


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


def parse_section_source(data: dict) -> ClientConfig:
    url = get_url(data)
    auth = get_auth(data.get("auth", {}))
    raise NotImplementedError()


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
        logger.error(
            "Missing required config <mark>auth method</mark>. "
            "Please provide from config file (<mark>source.auth.method</mark>) "
            "or environment variable (<mark>SECRETS_ENV_METHOD</mark>)."
        )
        return None

    method, _ = ensure_str("auth method", method)
    if not method:
        return None

    return secrets_env.auth.get_auth(method, data)

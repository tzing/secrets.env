import logging
import re
import typing
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from secrets_env.auth import get_auth
from secrets_env.config.types import Config, SecretPath, TLSConfig
from secrets_env.io import get_env_var

if typing.TYPE_CHECKING:
    from secrets_env.auth import Auth

T = typing.TypeVar("T")
T_ConfigData = Dict[str, Union[str, Dict]]

logger = logging.getLogger(__name__)


def parse_config(data: T_ConfigData) -> Optional[Config]:
    """Parse and validate raw configs, build it into structured object."""
    is_success = True

    section_source = data.get("source", {})
    section_source, ok = ensure_dict("source", section_source)
    is_success &= ok

    url, ok = get_url(section_source)
    is_success &= ok

    section_auth = section_source.get("auth", {})
    auth = parse_section_auth(section_auth)
    is_success &= auth is not None

    section_tls = section_source.get("tls", {})
    tls = parse_section_tls(section_tls)
    is_success &= tls is not None

    section_secrets = data.get("secrets", {})
    section_secrets, ok = ensure_dict("secrets", section_secrets)
    is_success &= ok

    secrets = parse_section_secrets(section_secrets)

    if not is_success:
        return None
    return Config(url=url, auth=auth, tls=tls, secret_specs=secrets)


def parse_section_auth(data: Union[T_ConfigData, str]) -> Optional["Auth"]:
    """Parse 'source.auth' section from raw configs."""
    if isinstance(data, str):
        # syntax sugar: `auth: <method>`
        data = {"method": data}

    data, _ = ensure_dict("source.auth", data)

    method, ok = get_auth_method(data)
    if not ok:
        return None

    return get_auth(method, data)


def parse_section_tls(data: T_ConfigData) -> Optional[TLSConfig]:
    """Parse 'tls' section from raw configs."""
    tls = {}
    is_success = True

    # ca cert
    path = get_env_var("SECRETS_ENV_CA_CERT", "VAULT_CACERT")
    if not path:
        path = data.get("ca_cert")

    if path:
        tls["ca_cert"], ok = ensure_path("source.tls.ca_cert", path)
        is_success &= ok

    # client cert
    path = get_env_var("SECRETS_ENV_CLIENT_CERT", "VAULT_CLIENT_CERT")
    if not path:
        path = data.get("client_cert")

    if path:
        tls["client_cert"], ok = ensure_path("source.tls.client_cert", path)
        is_success &= ok

    # client key
    path = get_env_var("SECRETS_ENV_CLIENT_KEY", "VAULT_CLIENT_KEY")
    if not path:
        path = data.get("client_key")

    if path:
        tls["client_key"], ok = ensure_path("source.tls.client_key", path)
        is_success &= ok

    return tls if is_success else {}


def parse_section_secrets(data: T_ConfigData) -> Dict[str, SecretPath]:
    """Parse 'secrets' section from raw configs."""
    secrets = {}

    for name, path in data.items():
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name):
            logger.warning(
                "Target environment variable '<data>%s</data>' is not a "
                "valid name. Skipping this variable.",
                name,
            )
            continue

        resource = parse_path(name, path)
        if resource:
            secrets[name] = resource

    return secrets


def get_url(section_source: T_ConfigData) -> Optional[str]:
    url = get_env_var("SECRETS_ENV_ADDR", "VAULT_ADDR")
    if not url:
        url = section_source.get("url", None)

    if not url:
        logger.error(
            "Missing required config '<mark>url</mark>'. "
            "Neither <mark>source.url</mark> in the config file "
            "nor environment variable <mark>SECRETS_ENV_ADDR</mark> is found."
        )
        return None, False

    return ensure_str("source.url", url)


def get_auth_method(data: T_ConfigData) -> Tuple[str, bool]:
    method = get_env_var("SECRETS_ENV_METHOD")
    if not method:
        method = data.get("method")

    if not method:
        logger.error(
            "Missing required config '<mark>auth method</mark>'. "
            "Neither <mark>source.auth.method</mark> in the config file "
            "nor environment variable <mark>SECRETS_ENV_METHOD</mark> is found."
        )
        return None, False

    return ensure_str("method", method)


def parse_path(name: str, spec: Union[str, Dict[str, str]]) -> Optional[SecretPath]:
    """Convert the secret path spec into the SecretPath object. Accepts both
    string input and dict input.
    """
    if isinstance(spec, str):
        # string input: path#key
        idx = spec.find("#")
        if 0 < idx < len(spec) - 1:
            path = spec[:idx]
            key = spec[idx + 1 :]
            return SecretPath(path, key)

        fail_msg = f"Failed to parse string '<data>{trimmed_str(spec)}</data>'"

    elif isinstance(spec, dict):
        # dict input: {"path": "foo", "key": "bar"}
        path = spec.get("path")
        key = spec.get("key")
        if isinstance(path, str) and isinstance(key, str):
            return SecretPath(path, key)

        fail_msg = "Missing required key <mark>path</mark> or <mark>key</mark>"

    logger.warning(
        "Target secret <data>%s</data> is invalid. %s. Skip this variable.",
        name,
        fail_msg,
    )

    return None


def _ensure_type(name: str, obj: T, expect: type, default: T) -> Tuple[T, bool]:
    """Ensure the a value is in desired type. Show warning and fallback to
    default value when the it is not valid."""
    if isinstance(obj, expect):
        return obj, True
    else:
        logger.warning(
            "Config <mark>%s</mark> is malformed: "
            "expect <mark>%s</mark> type, "
            "got '<data>%s</data>' (<mark>%s</mark> type)",
            name,
            expect.__name__,
            trimmed_str(obj),
            type(obj).__name__,
        )
        return default, False


def ensure_str(name: str, s: str) -> Tuple[str, bool]:
    return _ensure_type(name, s, str, None)


def ensure_dict(name: str, d: dict) -> Tuple[dict, bool]:
    return _ensure_type(name, d, dict, {})


def ensure_path(
    name: str, p: Union[str, Path], check_exist: bool = True
) -> Tuple[Path, bool]:
    # type check
    if isinstance(p, Path):
        ok = True
    else:
        p, ok = ensure_str(name, p)
        if not ok:
            return None, False
        p = Path(p)

    # existence check
    if check_exist and not (ok := p.exists()):
        logger.warning(
            "Config <mark>%s</mark> is malformed: path <data>%s</data> not exists",
            name,
            p,
        )
        p = None

    return p, ok


def trimmed_str(o: typing.Any) -> str:
    """Cast an object to str and trimmed."""
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

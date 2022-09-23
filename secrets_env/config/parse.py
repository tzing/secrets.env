import logging
import re
from typing import Any, Dict, Optional, Tuple, TypeVar, Union

from secrets_env.config.types import SecretPath
from secrets_env.utils import get_env_var

T = TypeVar("T")
T_ConfigData = Dict[str, Union[str, Dict]]

logger = logging.getLogger(__name__)


def get_url(section_source: T_ConfigData) -> Optional[str]:
    url = get_env_var("SECRETS_ENV_ADDR", "VAULT_ADDR")
    if not url:
        url = section_source.get("url", None)

    if not url:
        logger.error(
            "Missing required config '<data>url</data>'. "
            "Neither <mark>source.url</mark> in the config file "
            "nor environment variable <mark>SECRETS_ENV_ADDR</mark> is found."
        )
        return None, False

    return ensure_str("source.url", url)


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
            "Config <data>%s</data> is malformed: "
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


def trimmed_str(o: Any):
    """Cast an object to str and trimmed."""
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

import logging
import re
from typing import Any, Dict, Optional, Tuple, Union

from .types import SecretPath

logger = logging.getLogger(__name__)


def parse_section_secrets(data: Dict[str, Any]) -> Dict[str, SecretPath]:
    """Parse the 'secrets' section from raw configs."""
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


def ensure_type(var_name: str, type_name: str, obj: Any) -> Tuple[Any, bool]:
    """Ensure the a value is in desired type. Show warning and fallback to
    default value when the it is not valid."""
    __types = {
        "str": (str, None),
        "dict": (dict, {}),
    }

    type_, default = __types[type_name]
    if not isinstance(obj, type_):
        logger.warning(
            "Config <data>%s</data> is malformed: "
            "expect <mark>%s</mark> type, "
            "got '<data>%s</data>' (<mark>%s</mark> type)",
            var_name,
            type_name,
            trimmed_str(obj),
            type(obj).__name__,
        )

        return default, False

    return obj, True


def trimmed_str(o: Any):
    """Cast an object to str and trimmed."""
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

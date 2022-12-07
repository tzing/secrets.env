import logging
import re
import typing
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

import secrets_env.plugins
import secrets_env.providers.vault.auth
from secrets_env.providers.vault.config import (
    get_connection_info as parse_section_source,
)
from secrets_env.utils import ensure_dict

logger = logging.getLogger(__name__)

__regex_var_name = None


class SecretSource(typing.NamedTuple):
    path: str
    field: str


ConnectionInfo = Dict[str, Any]
SecretMapping = Dict[str, SecretSource]


class Config(TypedDict):
    client: ConnectionInfo
    secrets: SecretMapping


def parse_config(data: dict) -> Optional[Config]:
    """Parse and validate configs, build it into structured object."""
    # stop parse config when there's no target
    if not data.get("secrets"):
        logger.info("No target specificied. Stop loading secret.")
        return None

    # call hook
    hooks = secrets_env.plugins.get_hooks()
    hooks.add_extra_config(data=data)

    # shared flag
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

    return typing.cast(
        Config,
        {
            "client": config_source,
            "secrets": config_secrets,
        },
    )


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

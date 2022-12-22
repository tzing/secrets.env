import logging
import re
import typing
from typing import Dict, Optional, TypedDict, Union

import secrets_env.exceptions
import secrets_env.hooks
import secrets_env.providers
from secrets_env.utils import ensure_dict

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

logger = logging.getLogger(__name__)

__regex_var_name = None


class SecretSource(typing.NamedTuple):
    path: str
    field: str


SecretMapping = Dict[str, SecretSource]


class Config(TypedDict):
    client: "ProviderBase"
    secrets: SecretMapping


def parse_config(data: dict) -> Optional[Config]:
    """Parse and validate configs, build it into structured object."""
    # stop parse config when there's no target
    if not data.get("secrets"):
        logger.info("No target specificied. Stop loading secret.")
        return None

    # call hook
    hooks = secrets_env.hooks.get_hooks()
    hooks.add_extra_config(data=data)

    # shared flag
    is_success = True

    # get provider client
    data_source = data.get("source", {})
    data_source, ok = ensure_dict("source", data_source)
    is_success &= ok

    try:
        client = secrets_env.providers.get_provider(data_source)
    except secrets_env.exceptions.AuthenticationError as e:
        logger.error("Authentication error: %s", e)
        is_success = False
    except secrets_env.exceptions.ConfigError as e:
        logger.error("Conifguration error: %s", e)
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

    return Config(
        client=client,  # pyright: ignore[reportUnboundVariable]
        secrets=config_secrets,
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

        if not path_spec:
            logger.warning(
                "No source spec for variable <data>%s</data>. Skipping this variable.",
                name,
            )
            continue

        if not isinstance(path_spec, (str, dict)):
            logger.warning(
                "Invalid source spec type for variable <data>%s</data>. "
                "Skipping this variable.",
                name,
            )
            continue

        secrets[name] = path_spec

    return secrets

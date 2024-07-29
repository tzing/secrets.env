from __future__ import annotations

import json
import logging
import typing
from pathlib import Path

from pydantic import ValidationError

from secrets_env.config.lookup import find_local_config_file, find_user_config_file
from secrets_env.config.parser import LocalConfig
from secrets_env.config.reader import read, read_json_file
from secrets_env.exceptions import ConfigError
from secrets_env.utils import get_env_var

if typing.TYPE_CHECKING:
    from pydantic_core import Url


logger = logging.getLogger(__name__)


def load_local_config(path: Path | None) -> LocalConfig:
    """
    Load the configurations and formatted in to the typed structure.
    """
    if not path:
        if path_raw := get_env_var("SECRETS_ENV_CONFIG_FILE"):
            path = Path(path_raw)
            logger.debug(f"Get config file path from env var: {path}")
    if not path:
        path = find_local_config_file()
    if not path:
        raise ConfigError("Config file not found")

    logger.info("Read secrets.env config from <data>%s</data>", path)

    data = read(path)

    try:
        return LocalConfig.model_validate(data)
    except ValidationError as e:
        logger.error("Failed to parse config <data>%s</data>", path)
        for err in e.errors():
            field_name = ".".join(str(ll) for ll in err["loc"])

            user_input = err["input"]
            if isinstance(user_input, dict):
                user_input = json.dumps(user_input)

            logger.error(
                "  \u279C <mark>%s</mark> (input= <data>%s</data>)",
                field_name,
                user_input,
            )
            logger.error("    %s", err["msg"])

        raise ConfigError("Failed to parse config") from e


def load_user_config(url: Url) -> dict:
    """
    Load provider configurations from user's home directory.
    """
    path = find_user_config_file()
    if not path.is_file():
        logger.debug("User config file not exists")
        return {}

    config = read_json_file(path)
    if not config:
        logger.warning("User config file is invalid")
        return {}

    if provider_config := config.get(url.host, {}):
        logger.debug("Get provider config for %s from user config file", url.host)

    return provider_config

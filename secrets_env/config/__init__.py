from __future__ import annotations

import json
import logging
from pathlib import Path

from pydantic import ValidationError

from secrets_env.config.lookup import find_local_config_file
from secrets_env.config.parser import LocalConfig
from secrets_env.config.reader import read
from secrets_env.exceptions import ConfigError
from secrets_env.utils import get_env_var

logger = logging.getLogger(__name__)


def load_local_config(path: Path | None) -> LocalConfig:
    """
    Load the configurations and formated in to the typed structure.
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

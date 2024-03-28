from __future__ import annotations

import json
import logging
import typing

from pydantic import ValidationError

from secrets_env.config.lookup import find_local_config_file
from secrets_env.config.parser import LocalConfig
from secrets_env.config.reader import read
from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def load_local_config(path: Path | None) -> LocalConfig:
    """
    Load the configurations and formated in to the typed structure.
    """
    if not path:
        path = find_local_config_file()
    if not path:
        raise ConfigError("Config file not found")

    logger.info("Read secrets.env config from <data>%s</data>", path)

    data = read(path)

    try:
        return LocalConfig.model_validate(data)
    except ValidationError as e:
        logger.error("Failed to parse the config file: %s", path)
        for err in e.errors():
            field_name = ".".join(str(ll) for ll in err["loc"])

            user_input = err["input"]
            if isinstance(user_input, dict):
                user_input = json.dumps(user_input)

            logger.error(
                "  <mark>%s</mark> (input= <data>%s</data>)", field_name, user_input
            )
            logger.error("    %s", err["msg"])

        raise ConfigError("Failed to parse the config", path) from e

import logging
import typing
from typing import Optional

from secrets_env.config.lookup import find_local_config_file
from secrets_env.config.reader import read
from secrets_env.config0.parser import parse_config

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.config0.parser import Config

logger = logging.getLogger(__name__)


def load_config(path: Optional["Path"] = None) -> Optional["Config"]:
    """Load the configurations and formated in to the typed structure."""
    if not path:
        path = find_local_config_file()

    if not path:
        logger.info("Config file not found.")
        return None

    logger.info("Read secrets.env config from <data>%s</data>", path)

    data = read(path)
    return parse_config(data)

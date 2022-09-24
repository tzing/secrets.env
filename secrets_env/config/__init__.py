import logging
import typing
from typing import Optional

from secrets_env.config.file import (
    build_config_file_metadata,
    find_config_file,
    read_config_file,
)
from secrets_env.config.parse import parse_config

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.config.types import Config

logger = logging.getLogger(__name__)


def load_config(path: Optional["Path"] = None) -> Optional["Config"]:
    """Load the configurations and formated in to the typed structure."""
    if path:
        file_metadata = build_config_file_metadata(path)
    else:
        file_metadata = find_config_file()

    if not file_metadata:
        logger.info("Config file not found.")
        return None

    logger.info("Read secrets.env config from <data>%s</data>", file_metadata.path)

    data = read_config_file(file_metadata)
    if not data:
        logger.info("No content in the config file. Stop loading secrets.")
        return None

    return parse_config(data)

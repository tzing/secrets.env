import logging
import typing
from typing import Optional

from secrets_env.config.finder import find_config_file, get_config_file_metadata
from secrets_env.config.parser import parse_config
from secrets_env.config.reader import read_config_file

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.config.parser import Config

logger = logging.getLogger(__name__)


def load_config(path: Optional["Path"] = None) -> Optional["Config"]:
    """Load the configurations and formated in to the typed structure."""
    if path:
        file_metadata = get_config_file_metadata(path)
    else:
        file_metadata = find_config_file()

    if not file_metadata:
        logger.info("Config file not found.")
        return None

    logger.info("Read secrets.env config from <data>%s</data>", file_metadata.path)

    data = read_config_file(file_metadata)
    return parse_config(data)

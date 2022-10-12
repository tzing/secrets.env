__name__ = "secrets_env"
__version__ = "0.8.0"

import logging
from pathlib import Path
from typing import Dict

import secrets_env.config
import secrets_env.reader

logger = logging.getLogger(__name__)


def load_secrets(config_file: Path = None) -> Dict[str, str]:
    """Load secrets from vault and put them to environment variable."""
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    reader = secrets_env.reader.KVReader(config.url, config.auth)
    secrets = reader.get_values(config.secret_specs.values())

    output = {}
    for name, spec in config.secret_specs.items():
        value = secrets.get(spec)
        if not value:
            # skip logging. already show warning in `get_value`
            continue

        logger.debug("Load <info>%s</info>", name)
        output[name] = value

    if len(output) == len(config.secret_specs):
        logger.info("<info>%d</info> secrets loaded", len(secrets))
    else:
        logger.warning(
            "<error>%d</error> / %d secrets loaded",
            len(output),
            len(config.secret_specs),
        )

    return output

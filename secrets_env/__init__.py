__name__ = "secrets_env"
__version__ = "0.12.1"

import logging
from pathlib import Path
from typing import Dict, Optional

import secrets_env.config
import secrets_env.reader

logger = logging.getLogger(__name__)


def load_secrets(config_file: Optional[Path] = None) -> Dict[str, str]:
    """Load secrets from vault and put them to environment variable."""
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    reader = secrets_env.reader.KVReader(config.url, config.auth, config.tls)
    secrets = reader.get_values(config.secret_specs.values())

    output = {}
    for name, spec in config.secret_specs.items():
        value = secrets.get(spec)
        if not value:
            # skip logging. already show warning in `get_value`
            continue

        logger.debug("Loaded <data>$%s</data>", name)
        output[name] = value

    if len(output) == len(config.secret_specs):
        logger.info("<!important><mark>%d</mark> secrets loaded", len(secrets))
    else:
        logger.warning(
            "<!important><error>%d</error> / %d secrets loaded",
            len(output),
            len(config.secret_specs),
        )

    return output

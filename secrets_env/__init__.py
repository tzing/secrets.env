__name__ = "secrets_env"
__version__ = "0.22.0"

import logging
import pathlib
from typing import Dict, Optional

import secrets_env.config
import secrets_env.core
import secrets_env.exception

logger = logging.getLogger(__name__)


def load_secrets(
    config_file: Optional[pathlib.Path] = None,
) -> Dict[str, Optional[str]]:
    """Load secrets from vault and put them to environment variable."""
    # parse config
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    # read secrets
    reader = secrets_env.core.KVReader(**config["client"])

    try:
        secrets = reader.read_values(config["secrets"].values())
    except secrets_env.exception.AuthenticationError as e:
        logger.error(
            "<!important>\u26D4 Authentication error: %s. No secret loaded.", e.args[0]
        )
        return {}

    # build env var to secret mapping
    output = {}
    num_loaded = 0
    for name, spec in config["secrets"].items():
        if value := secrets.get(spec):
            num_loaded += 1
            logger.debug("Loaded <data>$%s</data>", name)
        output[name] = value

    if len(config["secrets"]) == num_loaded:
        logger.info(
            "<!important>\U0001F511 <mark>%d</mark> secrets loaded", len(secrets)
        )
    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded",
            num_loaded,
            len(config["secrets"]),
        )

    return output

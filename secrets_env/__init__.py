__name__ = "secrets_env"
__version__ = "0.15.0"

import logging
import pathlib
from typing import Dict, Optional

import secrets_env.config
import secrets_env.core
import secrets_env.exception

logger = logging.getLogger(__name__)


def load_secrets(config_file: Optional[pathlib.Path] = None) -> Dict[str, str]:
    """Load secrets from vault and put them to environment variable."""
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    reader = secrets_env.core.KVReader(
        url=config.url,
        auth=config.auth,
        ca_cert=config.tls.get("ca_cert"),
        client_cert=config.tls.get("client_cert"),
        client_key=config.tls.get("client_key"),
    )

    try:
        secrets = reader.read_values(config.secret_specs.values())
    except secrets_env.exception.AuthenticationError as e:
        logger.error(
            "<!important>\u26D4 Authentication error: %s. No secret loaded.", e.args[0]
        )
        return {}

    output = {}
    for name, spec in config.secret_specs.items():
        value = secrets.get(spec)
        if not value:
            # skip logging. already show warning in `get_value`
            continue

        logger.debug("Loaded <data>$%s</data>", name)
        output[name] = value

    if len(output) == len(config.secret_specs):
        logger.info(
            "<!important>\U0001F511 <mark>%d</mark> secrets loaded", len(secrets)
        )
    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded",
            len(output),
            len(config.secret_specs),
        )

    return output

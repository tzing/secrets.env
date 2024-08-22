from __future__ import annotations

import logging
import typing

import secrets_env.config
import secrets_env.exceptions
import secrets_env.utils
from secrets_env.version import __version__  # noqa: F401

if typing.TYPE_CHECKING:
    from pathlib import Path


def read_values(*, config: Path | None, strict: bool) -> dict[str, str]:
    """
    Load values from the providers and return them as a dictionary.

    Parameters
    ----------
    config : Path | None
        Path to config file. It searchs for config file when not given.
    strict : bool
        Enable strict mode. Raises an error when not all of the requests are
        successfully loaded.

    Returns
    -------
    dict[str, str]
        A dictionary of the loaded values.

    Raises
    ------
    ConfigError
        When the configuration is malformed.
    NoValue
        When failed to load a value and strict mode is enabled.
    """
    logger = logging.getLogger(__name__)

    if secrets_env.utils.get_bool_from_env_var("SECRETS_ENV_DISABLE"):
        logger.warning(
            "The environment variable 'SECRETS_ENV_DISABLE' is configured. "
            "The value loading process will be bypassed."
        )
        return {}

    # parse config
    cfg = secrets_env.config.load_local_config(config)

    if not cfg.requests:
        logger.info("Requests are absent. Skipping values loading.")
        return {}

    # if there is only one source, used as the default source
    default_source = None
    if len(cfg.providers) == 1:
        default_source = next(iter(cfg.providers))

    # load values
    output_values = {}
    is_success = True

    for request in cfg.requests:
        applied_source = request.source or default_source
        provider = cfg.providers[applied_source]
        try:
            output_values[request.name] = provider(request)
            logger.debug(f"Loaded <data>{request.name}</data>")
        except secrets_env.exceptions.NoValue:
            is_success = False

    # report
    if is_success:
        logger.info(
            "<!important>\U0001F511 <mark>%d</mark> secrets loaded", len(cfg.requests)
        )

    elif strict:
        logger.error(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded. "
            "Not satisfied the requirement.",
            len(output_values),
            len(cfg.requests),
        )
        raise secrets_env.exceptions.NoValue

    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded",
            len(output_values),
            len(cfg.requests),
        )

    return output_values

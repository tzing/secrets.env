__name__ = "secrets_env"
__version__ = "0.26.3"

import logging
import typing

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.provider import ProviderBase, RequestSpec

logger = logging.getLogger(__name__)


def load_secrets(
    config_file: typing.Optional["Path"] = None, strict: bool = True
) -> typing.Optional[typing.Dict[str, str]]:
    """Load secrets from vault and put them to environment variable.

    Parameters
    ----------
    config_file : Path
        Path to config file. It searchs for config file when not given.
    strict : bool
        Enable strict mode. Returns :py:obj:`None` when not all of the secrets
        successfully loaded.
    """
    import secrets_env.config

    # parse config
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    # load values
    output_values = {}
    for request in config["requests"]:
        name = request["name"]

        provider = config["providers"].get(request["provider"])
        if not provider:
            logger.warning(
                "Provider <data>%s</data> not exists. Skip %s.",
                request["provider"],
                request["name"],
            )
            continue

        logger.debug("Read %s from %s", name, request["spec"])
        value = read1(provider, name, request["spec"])

        if value:
            logger.debug("Read <data>$%s</data> successfully", name)
            output_values[name] = value
        else:
            logger.warning("Failed to read <data>$%s</data>", name)

    # report
    num_expected = len(config["requests"])
    num_loaded = len(output_values)

    if num_expected == num_loaded:
        logger.info(
            "<!important>\U0001F511 <mark>%d</mark> secrets loaded", num_expected
        )

    elif strict:
        logger.error(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets read. "
            "Not satisfied the requirement.",
            num_loaded,
            num_expected,
        )
        return None

    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded",
            num_loaded,
            num_expected,
        )

    return output_values

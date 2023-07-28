import logging
import typing

from secrets_env.version import __version__  # noqa: F401

if typing.TYPE_CHECKING:
    from pathlib import Path


def read_values(
    config_file: typing.Optional["Path"] = None, strict: bool = False
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
    import secrets_env.collect
    import secrets_env.config

    # parse config
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return None

    # load values
    output_values = secrets_env.collect.read_values(config)

    # report
    logger = logging.getLogger(__name__)

    num_expected = len(config["requests"])
    num_loaded = len(output_values)

    if not num_expected:
        return {}

    elif num_expected == num_loaded:
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

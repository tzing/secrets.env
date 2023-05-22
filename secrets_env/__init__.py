__name__ = "secrets_env"
__version__ = "0.26.2"

import logging
import pathlib
import typing

import secrets_env.config
import secrets_env.exceptions
from secrets_env.provider import ProviderBase, RequestSpec

logger = logging.getLogger(__name__)


def load_secrets(
    config_file: typing.Optional[pathlib.Path] = None, strict: bool = True
) -> typing.Dict[str, str]:
    """Load secrets from vault and put them to environment variable."""
    # parse config
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    # load secret
    output = {}
    for request in config["requests"]:
        name = request["name"]

        provider = config["providers"].get(request["provider"])
        if not provider:
            logger.warning(
                "Provider <data>%s</data> not exists. Skip %s.",
                request["provider"],
                request["name"],
            )
            output[name] = None
            continue

        output[name] = value = read1(provider, name, request["spec"])
        if value:
            logger.debug("Loaded <data>$%s</data>", name)

    # report
    num_expected = len(config["requests"])
    num_loaded = sum(1 for v in output.values() if v is not None)

    if num_expected == num_loaded:
        logger.info(
            "<!important>\U0001F511 <mark>%d</mark> secrets loaded", num_expected
        )
    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26A0\uFE0F  <error>%d</error> / %d secrets loaded",
            num_loaded,
            num_expected,
        )

        if strict:
            return {}

    return output


def read1(provider: ProviderBase, name: str, spec: RequestSpec) -> typing.Optional[str]:
    """Read single value.

    This function wraps :py:meth:`secrets_env.provider.ProviderBase.get` and
    captures all exceptions.
    """
    # type checking
    if not isinstance(provider, ProviderBase):
        raise secrets_env.exceptions.TypeError("provider", "secret provider", provider)
    if not isinstance(name, str):
        raise secrets_env.exceptions.TypeError("name", str, name)
    if not isinstance(spec, (str, dict)):
        raise secrets_env.exceptions.TypeError("spec", dict, spec)

    # run
    try:
        return provider.get(spec)
    except secrets_env.exceptions.AuthenticationError as e:
        logger.error(
            "<!important>\u26D4 Authentication error on %s provider: %s.",
            provider.type,
            e.args[0],
        )
    except secrets_env.exceptions.ConfigError as e:
        logger.warning("Config for %s is malformed: %s. Skip this variable.", name, e)
    except secrets_env.exceptions.ValueNotFound:
        logger.warning("Secret for %s not found. Skip this variable.", name)
    except Exception as e:
        logger.error("Error requesting secret for %s. Skip this variable.", name)
        logger.debug(
            "Requested path= %s, Error= %s, Msg= %s",
            spec,
            type(e).__name__,
            e.args,
            exc_info=True,
        )
    return None

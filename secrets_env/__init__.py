__name__ = "secrets_env"
__version__ = "0.24.0"

import logging
import pathlib
import typing
from typing import Dict, Optional

import secrets_env.config
import secrets_env.exceptions
import secrets_env.provider
import secrets_env.providers.vault.provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase, SourceSpec

logger = logging.getLogger(__name__)


def load_secrets(
    config_file: Optional[pathlib.Path] = None, strict: bool = True
) -> Dict[str, str]:
    """Load secrets from vault and put them to environment variable."""
    # parse config
    config = secrets_env.config.load_config(config_file)
    if not config:
        # skip logging. already show error in `load_config`
        return {}

    # build env var to secret mapping
    output = {}
    for name, spec in config["secrets"].items():
        value = read1(
            config["client"],
            name,
            spec,  # pyright: ignore[reportGeneralTypeIssues]; TODO
        )
        output[name] = value
        if value is not None:
            logger.debug("Loaded <data>$%s</data>", name)

    # report
    num_expected = len(config["secrets"])
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


def read1(provider: "ProviderBase", name: str, spec: "SourceSpec") -> Optional[str]:
    """Read single value.

    This function wraps :py:meth:`~secrets_env.provider.ProviderBase.get` and
    captures all exceptions."""
    # type checking
    if not isinstance(provider, secrets_env.provider.ProviderBase):
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
            "<!important>\u26D4 Authentication error: %s. No secret loaded.",
            e.args[0],
        )
    except secrets_env.exceptions.ConfigError as e:
        logger.warning("Config for %s is malformed: %s. Skip this variable.", name, e)
    except secrets_env.exceptions.SecretNotFound:
        logger.warning("Secret for %s not found. Skip this variable.", name)
    except Exception as e:
        logger.error("Error requesting secret for %s. Skip this variable.", name)
        logger.debug(
            "Requested path= %s, Error= %s, Msg= %s",
            spec,
            type(e).__name__,
            e.args[0],
            exc_info=True,
        )
    return None

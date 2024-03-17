from __future__ import annotations

import logging
import typing

if typing.TYPE_CHECKING:
    from secrets_env.config0.parser import Config
    from secrets_env.provider import Provider, RequestSpec

logger = logging.getLogger(__name__)


def read_values(config: Config) -> dict[str, str]:
    """Request values from providers."""
    output_values = {}
    for request in config["requests"]:
        name = request["name"]

        provider = config["providers"].get(request["provider"])
        if not provider:
            logger.warning(
                "Provider <data>%s</data> not exists. Skip <data>$%s</data>.",
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

    return output_values


def read1(provider: Provider, name: str, spec: RequestSpec) -> str | None:
    """Read single value.

    This function wraps :py:meth:`secrets_env.provider.ProviderBase.get` and
    captures all exceptions.
    """
    import secrets_env.exceptions
    from secrets_env.provider import Provider

    # type checking
    if not isinstance(provider, Provider):
        raise TypeError(
            f'Expected "provider" to be a credential provider class, '
            f"got {type(provider).__name__}"
        )
    if not isinstance(name, str):
        raise TypeError(f'Expected "name" to be a string, got {type(name).__name__}')
    if not isinstance(spec, (str, dict)):
        raise TypeError(
            f'Expected "spec" to be a string or dict, got {type(spec).__name__}'
        )

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

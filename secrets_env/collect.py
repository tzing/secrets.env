import logging
import typing

if typing.TYPE_CHECKING:
    from secrets_env.config.parser import Config
    from secrets_env.provider import ProviderBase, RequestSpec

logger = logging.getLogger(__name__)


def read_values(config: "Config"):
    ...


def read1(
    provider: "ProviderBase", name: str, spec: "RequestSpec"
) -> typing.Optional[str]:
    """Read single value.

    This function wraps :py:meth:`secrets_env.provider.ProviderBase.get` and
    captures all exceptions.
    """
    import secrets_env.exceptions
    from secrets_env.provider import ProviderBase

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

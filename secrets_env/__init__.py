from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import typing

import secrets_env.config
import secrets_env.exceptions
import secrets_env.utils
from secrets_env.provider import AsyncProvider, Provider, Request
from secrets_env.version import __version__  # noqa: F401

if typing.TYPE_CHECKING:
    from asyncio import Task
    from pathlib import Path

logger = logging.getLogger(__name__)


async def load_values(*, config: Path | None, strict: bool) -> dict[str, str]:
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
    if secrets_env.utils.get_bool_from_env_var("SECRETS_ENV_DISABLE"):
        logger.warning(
            "The environment variable 'SECRETS_ENV_DISABLE' is configured. "
            "The value loading process will be bypassed."
        )
        return {}

    # parse config
    cfg = secrets_env.config.load_local_config(config)

    if not cfg.secrets:
        logger.info("Requests are absent. Skipping values loading.")
        return {}

    # index providers
    providers: dict[str | None, Provider | AsyncProvider] = {
        provider.name: provider for provider in cfg.sources
    }

    if len(cfg.sources) == 1:
        providers[None] = cfg.sources[0]

    # submit requests
    lock = asyncio.Lock()

    async def _fetch(request: Request) -> tuple[Request, str]:
        nonlocal providers, lock

        provider = providers[request.source]

        if isinstance(provider, AsyncProvider):
            value = await provider(request)
        else:
            # TODO remove lock after the sync provider is thread-safe
            async with lock:
                value = provider(request)

        return request, value

    tasks: list[Task[tuple[Request, str]]] = []
    for request in cfg.requests:
        tasks.append(asyncio.create_task(_fetch(request)))

    # collect results
    output_values = {}
    is_success = True

    for task in asyncio.as_completed(tasks):
        try:
            request, value = await task
        except secrets_env.exceptions.NoValue:
            is_success = False
            continue

        logger.debug(f"Loaded <data>{request.name}</data>")
        output_values[request.name] = value

    # report
    if is_success:
        logger.info(
            "<!important>\U0001f511 <mark>%d</mark> secrets loaded", len(cfg.requests)
        )

    elif strict:
        logger.error(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26a0\ufe0f  <error>%d</error> / %d secrets loaded. "
            "Not satisfied the requirement.",
            len(output_values),
            len(cfg.requests),
        )
        raise secrets_env.exceptions.NoValue

    else:
        logger.warning(
            # NOTE need extra whitespace after the modifier (\uFE0F)
            "<!important>\u26a0\ufe0f  <error>%d</error> / %d secrets loaded",
            len(output_values),
            len(cfg.requests),
        )

    return output_values


def load_values_sync(*, config: Path | None, strict: bool) -> dict[str, str]:
    """The synchronous version of :py:func:`load_values`."""

    def _worker():
        return asyncio.run(load_values(config=config, strict=strict))

    # trick: use one-off thread pool to create dedicated event loop
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(_worker).result()

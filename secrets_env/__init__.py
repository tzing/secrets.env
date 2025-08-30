from __future__ import annotations

import asyncio
import itertools
import logging
import typing

import secrets_env.config
import secrets_env.exceptions
import secrets_env.utils
from secrets_env.version import __version__  # noqa: F401

if typing.TYPE_CHECKING:
    from asyncio import Task
    from pathlib import Path
    from typing import Literal

    from secrets_env.provider import AsyncProvider, Provider, Request

    KeyValuePair = tuple[str, str | Literal[None]]

logger = logging.getLogger(__name__)


async def read_values(*, config: Path | None, strict: bool) -> dict[str, str]:
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

    # group requests by provider
    requests: dict[str | None, list[Request]] = {}
    for request in cfg.requests:
        desired_source = request.source or default_source
        requests.setdefault(desired_source, []).append(request)

    # load values
    tasks: list[Task[list[KeyValuePair]]] = []
    for provider_name, request_group in requests.items():
        task = asyncio.create_task(
            _get_values_from_provider(cfg.providers[provider_name], request_group)
        )
        tasks.append(task)

    output_values = {}
    is_success = True
    for name, value in itertools.chain.from_iterable(await asyncio.gather(*tasks)):
        if value is None:
            is_success = False
        else:
            output_values[name] = value

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


async def _get_values_from_provider(
    provider: Provider | AsyncProvider, requests: list[Request]
) -> list[KeyValuePair]:
    collected = []
    for request in requests:
        logger.debug(f"Loading <data>{request.name}</data>...")

        try:
            value = provider(request)
            if isinstance(value, typing.Coroutine):
                value = await value
        except secrets_env.exceptions.NoValue:
            collected.append((request.name, None))
            continue

        collected.append((request.name, value))

    return collected

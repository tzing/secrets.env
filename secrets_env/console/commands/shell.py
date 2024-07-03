from __future__ import annotations

import logging
import os
from pathlib import Path

import click

import secrets_env
import secrets_env.console.shells
from secrets_env.console.core import ExitCode, entrypoint, exit, with_output_options
from secrets_env.exceptions import ConfigError, NoValue


@entrypoint.command()
@click.option(
    "-f",
    "--config",
    type=click.Path(exists=True, file_okay=True, path_type=Path),
    help="Specify configuration file.",
)
@click.option(
    "--partial",
    is_flag=True,
    help="Accept partial values loading. Or stop when failed to load any value.",
)
@with_output_options
def shell(config: Path, partial: bool):
    """
    Spawns a shell with the specified environment variables loaded.
    """
    logger = logging.getLogger(__name__)

    if os.getenv("SECRETS_ENV_ACTIVE"):
        logger.error("Secrets.env is already activated")
        exit(ExitCode.NestedEnvironment)

    if os.getenv("POETRY_ACTIVE"):
        logger.warning(
            "Detected Poetry environment. "
            "Some variables may be overwritten in the nested environment."
        )
        logger.warning("Please consider using secrets.env as a Poetry plugin.")
    elif os.getenv("VIRTUAL_ENV"):
        logger.warning(
            "Detected Python virtual environment. "
            "Some variables may be overwritten in the nested environment."
        )
        logger.warning("Please consider deactivating the virtual environment first.")

    try:
        values = secrets_env.read_values(config=config, strict=not partial)
    except (ConfigError, NoValue) as e:
        logger.error(str(e))
        exit(ExitCode.ValueNotFound)

    if not values:
        logger.warning("No values found. Secrets.env will terminate smoothly.")
        exit(ExitCode.Success)

    shell = secrets_env.console.shells.get_shell()
    shell.activate(values)

from __future__ import annotations

import logging
from pathlib import Path

import click

import secrets_env
import secrets_env.console.shells
import secrets_env.utils
from secrets_env.console.core import entrypoint, exit, with_output_options
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

    if secrets_env.utils.is_secrets_env_active():
        logger.error("Secrets.env is already activated")
        raise click.Abort from None

    try:
        values = secrets_env.read_values(config=config, strict=not partial)
    except (ConfigError, NoValue) as e:
        logger.error(str(e))
        raise click.Abort from None

    if not values:
        logger.warning("No values found. Secrets.env will terminate smoothly.")
        exit(0)

    shell = secrets_env.console.shells.get_shell()
    shell.activate(values)

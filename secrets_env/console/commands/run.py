import logging
import os
import subprocess
from pathlib import Path
from typing import Sequence

import click

import secrets_env
from secrets_env.console.core import entrypoint, exit, with_output_options
from secrets_env.exceptions import ConfigError, NoValue
from secrets_env.utils import inject_environs, is_secrets_env_active


class RunCommand(click.Command):
    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Writes the usage line into the formatter.

        This is a low-level method called by :meth:`get_usage`.
        """
        formatter.write_usage(ctx.command_path, "[OPTIONS] [--] COMMAND [ARGS]...")


@entrypoint.command(
    cls=RunCommand,
    context_settings={
        "ignore_unknown_options": True,
    },
)
@click.argument(
    "args",
    nargs=-1,
    type=click.UNPROCESSED,
    required=True,
)
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
def run(args: Sequence[str], config: Path, partial: bool):
    """
    Load values into environment variable then run the command.

    Make secrets.env reads the configuration file, loads values from the defined
    sources, sets the environment variables, and then executes the specified
    command within this updated environment.

    Note that the command should be separated from the options with a double
    dash (`--`), in order to avoid ambiguity.
    """
    logger = logging.getLogger(__name__)

    # prevent double activation
    if is_secrets_env_active():
        logger.error("secrets.env is already active")
        raise click.Abort from None

    # prepare environment variable set
    try:
        values = secrets_env.read_values(config=config, strict=not partial)
    except (ConfigError, NoValue) as e:
        logger.error("%s", e)
        raise click.Abort from None

    # run
    logger.debug("exec> %s", " ".join(args))

    with inject_environs(values):
        proc = subprocess.run(args, env=os.environ)

    exit(proc.returncode)

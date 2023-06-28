import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import click

import secrets_env
from secrets_env.click import add_output_options, entrypoint


@entrypoint.command(
    context_settings={
        "ignore_unknown_options": True,
    }
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED, required=True)
@click.option(
    "-C",
    "--config",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, resolve_path=True, path_type=Path
    ),
    help="Specify an alternative configuration file.",
)
@click.option(
    "--strict/--no-strict",
    is_flag=True,
    default=True,
    show_default=True,
    help="Use strict mode. Stop run when not all of the values loaded.",
)
@add_output_options
def run(args: Sequence[str], config: Path, strict: bool):
    """Loads secrets into environment variable then run the command."""
    # prepare environment variable set
    secrets = secrets_env.read_values(config, strict)
    if secrets is None:
        sys.exit(128)

    environ = os.environ.copy()
    environ.update(secrets)

    # run
    logger = logging.getLogger(__name__)
    logger.debug("exec> %s", " ".join(args))

    result = subprocess.run(args, env=environ)

    sys.exit(result.returncode)

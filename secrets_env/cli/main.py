import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import click

import secrets_env
from secrets_env.cli.output import add_output_options

logger = logging.getLogger(__name__)


@click.group(
    context_settings={
        "help_option_names": ["-h", "--help"],
    }
)
@click.version_option(
    secrets_env.__version__,
    "-V",
    "--version",
    prog_name=secrets_env.__name__,
)
def main():
    """Secrets.env is a tool that could put secrets from vault to environment
    variables."""


@main.command(
    context_settings={
        "ignore_unknown_options": True,
    }
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "-f",
    "--file",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, resolve_path=True, path_type=Path
    ),
    help="Specify an alternative configuration file.",
)
@add_output_options
def run(args: Tuple[str, ...], file: Path):
    """Loads secrets into environment variable then run the command."""
    # prepare environment variable set
    environ = os.environ.copy()
    environ.update(secrets_env.load_secrets(file))

    # run
    logger.debug("exec> %s", " ".join(args))
    result = subprocess.run(args, env=environ)

    sys.exit(result.returncode)

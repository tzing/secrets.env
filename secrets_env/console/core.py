from __future__ import annotations

__all__ = ["entrypoint", "exit", "with_output_options"]

import sys
import typing

import click

import secrets_env.version
from secrets_env.console.decorators import with_output_options

if typing.TYPE_CHECKING:
    from typing import NoReturn


def exit(code: int) -> NoReturn:
    # just in case `site.exit()` is not available
    sys.exit(code)


@click.group(
    context_settings={
        "help_option_names": ["-h", "--help"],
    }
)
@click.version_option(secrets_env.version.__version__)
def entrypoint():
    """Connect the credential store to your app."""

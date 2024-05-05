from __future__ import annotations

__all__ = ["entrypoint", "with_output_options"]

import click

import secrets_env.version
from secrets_env.realms.click import with_output_options


@click.group(
    context_settings={
        "help_option_names": ["-h", "--help"],
    }
)
@click.version_option(secrets_env.version.__version__)
def entrypoint():
    """Connect the credential store to your development environment."""

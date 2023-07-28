import click

from secrets_env._metadata import __version__
from secrets_env.click import entrypoint


@entrypoint.command()
def version():
    """Show current version and status"""
    click.echo(__version__)

import click

from secrets_env._metadata import __name__, __version__
from secrets_env.click import entrypoint


@entrypoint.command()
def version():
    """Show current version and status"""
    click.echo(f"{__name__} {__version__}")

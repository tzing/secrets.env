import click

from secrets_env.click import entrypoint


@entrypoint.command()
def version():
    """Show current version and status"""
    from secrets_env.version import __version__

    click.echo(__version__)

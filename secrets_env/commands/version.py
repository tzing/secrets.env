import click

from secrets_env.click import entrypoint


@entrypoint.command()
def version():
    """Show current version."""
    from secrets_env.version import __version__

    click.echo(__version__)

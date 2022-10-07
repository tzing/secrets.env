import click

import secrets_env


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

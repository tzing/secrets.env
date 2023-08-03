import sys

import click

from secrets_env.click import entrypoint, setup_logging


@entrypoint.group("keyring")
def group():
    """Manage credential using system keyring service."""
    setup_logging()


@group.command()
def status():
    """Check if keyring is available."""
    if not is_keyring_available():
        sys.exit(2)
    click.echo("ok")


@group.command("set")
@click.option(
    "-H", "--host", required=True, help="Specify the host for this credential set."
)
@click.option("-t", "--token", help="Token to be stored.")
@click.option("-u", "--user", help="Username.")
@click.option("-p", "--password", help="Password. This app will prompt for input.")
def command_set(host: str, token: str, user: str, password: str):
    """Store credential in system keyring.

    You must specify exactly one of the following options: '-t' / '--token' or
    '-u' / '--user'. These options are mutually exclusive.
    """
    if not is_keyring_available():
        sys.exit(2)

    key = get_keyring_key(host, token, user)

    if user:
        if not password:
            password = click.prompt("Password", hide_input=True)
        if not password:
            raise click.UsageError("Missing password (option '-p' / '--password').")
        secret = password

    else:
        secret = token

    import keyring
    import keyring.errors

    try:
        keyring.set_password("secrets.env", key, secret)
    except keyring.errors.PasswordSetError:
        click.secho("Failed to set password", fg="red", err=True)
        sys.exit(1)


@group.command("del")
@click.option(
    "-H", "--host", required=True, help="Specify the host for this credential set."
)
@click.option("-t", "--token", help="Token to be stored.")
@click.option("-u", "--user", help="Username.")
def command_del(host: str, token: str, user: str):
    """Remove a credential from system keyring.

    You must specify exactly one of the following options: '-t' / '--token' or
    '-u' / '--user'. These options are mutually exclusive.
    """
    if not is_keyring_available():
        sys.exit(2)

    key = get_keyring_key(host, token, user)

    import keyring
    import keyring.errors

    try:
        keyring.delete_password("secrets.env", key)
    except keyring.errors.PasswordDeleteError:
        ...  # ignore


def get_keyring_key(host: str, token: str, user: str) -> str:
    if not token and not user:
        raise click.UsageError("Missing option '-t' / '--token' or '-u' / '--user'.")
    if token and user:
        raise click.UsageError(
            "Option '-t' / '--token' and '-u' / '--user' are mutually exclusive."
        )

    from secrets_env.utils import create_keyring_login_key, create_keyring_token_key

    if user:
        return create_keyring_login_key(host, user)
    else:
        return create_keyring_token_key(host)


def is_keyring_available() -> bool:
    try:
        import keyring
        import keyring.backends.fail
    except ImportError:
        click.secho(
            "Dependency `keyring` not found. "
            "Please install secrets.env with extras `[keyring]`.",
            fg="red",
            err=True,
        )
        return False

    if isinstance(keyring.get_keyring(), keyring.backends.fail.Keyring):
        click.secho("Keyring service is not available", fg="red", err=True)
        return False

    return True

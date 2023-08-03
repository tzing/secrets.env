import logging
import sys

import click

from secrets_env.click import add_output_options, entrypoint

logger = logging.getLogger(__name__)


@entrypoint.group("keyring")
def group():
    """Manage credential using system keyring service."""


@group.command()
def status():
    """Check if keyring is available."""
    if not is_keyring_available():
        sys.exit(2)
    click.echo("ok")


@group.command("set")
@click.argument("host")
@click.argument("target")
@click.argument("value", required=False)
@add_output_options
def command_set(host: str, target: str, value: str):
    """Store credential in system keyring.

    HOST is the hostname/url to the vault that uses this credential.

    TARGET is the target credential name. It could be `token` for auth token, or
    the username for login.

    VALUE is the credential value. This app will prompt for input when it is not
    passed as an argument.
    """
    if not is_keyring_available():
        sys.exit(2)

    # build key
    from secrets_env.utils import create_keyring_login_key, create_keyring_token_key

    if target == "token":
        key = create_keyring_token_key(host)
        name = "token"
    else:
        key = create_keyring_login_key(host, target)
        name = "password"

    # get value
    if not value:
        value = click.prompt(name, hide_input=True)
    if not value:
        raise click.UsageError("Missing credential value.")

    # save value
    import keyring
    import keyring.errors

    logger.debug("Set keyring value with key %s", key)

    try:
        keyring.set_password("secrets.env", key, value)
    except keyring.errors.PasswordSetError:
        click.secho(f"Failed to save {name}", fg="red", err=True)
        sys.exit(1)


@group.command("del")
@click.argument("host")
@click.argument("target")
@add_output_options
def command_del(host: str, target: str):
    """Remove a credential from system keyring.

    HOST is the hostname/url to the vault that uses this credential.

    TARGET is the target credential name. It could be `token` for auth token, or
    the username for login.
    """
    if not is_keyring_available():
        sys.exit(2)

    # build key
    from secrets_env.utils import create_keyring_login_key, create_keyring_token_key

    if target == "token":
        key = create_keyring_token_key(host)
    else:
        key = create_keyring_login_key(host, target)

    # remove
    import keyring
    import keyring.errors

    try:
        keyring.delete_password("secrets.env", key)
        logger.debug("Remove %s from keyring", key)
    except keyring.errors.PasswordDeleteError:
        logger.debug("Failed to remove %s from keyring", key)


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

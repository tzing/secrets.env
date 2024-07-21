from __future__ import annotations

import logging
import sys

import click
from pydantic_core import Url

from secrets_env.console.core import entrypoint, with_output_options

logger = logging.getLogger(__name__)


class UrlParam(click.ParamType):
    """Parameter type for URL."""

    name = "url"

    def convert(self, value: str, param, ctx):
        """
        Convert value to URL object.

        The schema does not matter. It will be discarded later in `create_keyring_login_key`.
        """
        if "://" in value:
            return Url(value)
        return Url(f"https://{value}")


@entrypoint.group("keyring")
def group():
    """
    Manage credential using system keyring service.
    """


@group.command("set")
@click.argument("host", type=UrlParam())
@click.argument("username")
@click.option("-p", "--password", help="Password for login")
@click.option("--password-stdin", is_flag=True, help="Read the password from stdin")
@with_output_options
def command_set(host: Url, username: str, password: str, password_stdin: bool):
    """
    Store credential in system keyring.
    """
    assert_keyring_available()

    # validate arguments
    if password is None and not password_stdin:
        raise click.UsageError("Missing option: '--password' or '--password-stdin'")
    if password is not None and password_stdin:
        raise click.UsageError(
            "Cannot use '--password' and '--password-stdin' together"
        )

    if password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")

    # proceed
    import keyring
    import keyring.errors

    from secrets_env.utils import create_keyring_login_key

    key = create_keyring_login_key(host, username)
    logger.debug("Set keyring value with key %s", key)

    try:
        keyring.set_password("secrets.env", key, password)
    except keyring.errors.PasswordSetError:
        click.secho("Failed to save password", fg="red")
        raise click.Abort from None

    click.echo("Password saved")


@group.command("del")
@click.argument("host", type=UrlParam())
@click.argument("username")
@with_output_options
def command_del(host: Url, username: str):
    """
    Remove a credential from system keyring.
    """
    assert_keyring_available()

    import keyring
    import keyring.errors

    from secrets_env.utils import create_keyring_login_key

    key = create_keyring_login_key(host, username)
    logger.debug("Remove %s from keyring", key)

    try:
        keyring.delete_password("secrets.env", key)
        click.echo("Password removed")
    except keyring.errors.PasswordDeleteError:
        logger.debug("Failed to remove %s from keyring", key)
        click.echo("Password not found")


def assert_keyring_available():
    try:
        import keyring
        import keyring.backends.fail
    except ImportError as e:
        logger.error("Dependency `keyring` not found")
        logger.error("Please install secrets.env with extra `[keyring]`")
        raise click.Abort from e

    if isinstance(keyring.get_keyring(), keyring.backends.fail.Keyring):
        logger.error("Keyring service is not available")
        raise click.Abort from None

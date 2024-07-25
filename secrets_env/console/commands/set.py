from __future__ import annotations

import logging

import click
from pydantic_core import Url

import secrets_env.utils
from secrets_env.console.core import entrypoint, with_output_options

logger = logging.getLogger(__name__)


class VisibleOption(click.Option):
    """
    A :py:class:`click.Option` subclass that shows the option in the help text.
    """

    def get_usage_pieces(self, ctx: click.Context) -> list[str]:
        return [self.opts[-1], self.make_metavar()]


class UrlParam(click.ParamType):
    """
    Parameter type for URL host.
    """

    name = "url"

    def convert(self, value: str, param, ctx) -> Url:
        if "://" in value:
            return Url(value)
        elif "." in value:
            return Url(f"https://{value}")
        raise click.BadParameter("Invalid URL")


@entrypoint.group("set")
def group_set():
    """
    Manage value in per-user storage.

    This command group provides a way to store user-specific information in a
    secure and convenient manner. By storing values in a per-user configuration,
    you can avoid the need to re-enter sensitive information each time you run
    secrets.env.
    """


@group_set.command("password")
@click.option(
    "-t",
    "--target",
    type=UrlParam(),
    required=True,
    help="Specify target host name for which the password will be used.",
    cls=VisibleOption,
)
@click.option(
    "-u",
    "--username",
    required=True,
    help="Specify the username for the target host.",
    cls=VisibleOption,
)
@click.option(
    "-p",
    "--password",
    help=(
        "Specify the password value to store. "
        "Set to `-` to read from stdin. "
        "If not provided, a prompt will be shown."
    ),
    cls=VisibleOption,
)
@click.option(
    "-d",
    "--delete",
    is_flag=True,
    help="Delete the stored password for the target host.",
)
@with_output_options
def command_set_password(
    target: Url, username: str, password: str | None, delete: bool
):
    """
    Store password in system keyring.
    """
    assert_keyring_available()

    # early return when delete flag is set
    if delete:
        return remove_password(target, username)

    # get value
    if password == "-":
        password = click.get_text_stream("stdin").readline().rstrip("\r\n")
    if not password:
        password = secrets_env.utils.prompt("Password", hide_input=True)
    if not password:
        raise click.UsageError("Value (password) is required.")

    set_password(target, username, password)


def set_password(url: Url, username: str, password: str):
    import keyring
    import keyring.errors

    key = secrets_env.utils.create_keyring_login_key(url, username)

    try:
        keyring.set_password("secrets.env", key, password)
    except keyring.errors.PasswordSetError:
        logger.error("Failed to save password")
        raise click.Abort from None

    logger.info("Password saved")


def remove_password(url: Url, username: str):
    import keyring
    import keyring.errors

    key = secrets_env.utils.create_keyring_login_key(url, username)

    logger.debug("Removing %s from keyring", key)

    try:
        keyring.delete_password("secrets.env", key)
    except keyring.errors.PasswordDeleteError:
        logger.debug("Failed to remove %s from keyring", key)

    logger.info("Password removed")


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

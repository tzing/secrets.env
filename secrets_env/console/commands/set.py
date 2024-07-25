from __future__ import annotations

import logging

import click
from pydantic_core import Url

from secrets_env.console.core import entrypoint, with_output_options

logger = logging.getLogger(__name__)


class VisibleOption(click.Option):
    """
    A :py:class:`click.Option` subclass that shows the option in the help text.
    """

    def get_usage_pieces(self, ctx: click.Context) -> list[str]:
        return [self.opts[-1], self.make_metavar()]


class HostParam(click.ParamType):
    """
    Parameter type for URL host.
    """

    name = "host"

    def convert(self, value: str, param, ctx) -> str:
        host = None
        if "://" in value:
            host = Url(value).host
        elif "." in value:
            host = Url(f"https://{value}").host
        if not host:
            raise click.BadParameter("Invalid host")
        return host


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
    type=HostParam(),
    required=True,
    help="Specify target host name for which the password will be used.",
    cls=VisibleOption,
)
@click.option(
    "-u",
    "--username",
    type=HostParam(),
    required=True,
    help="Specify the username for the target host.",
    cls=VisibleOption,
)
@click.option(
    "-v",
    "--value",
    help=(
        "Specify the password value to store. "
        "Set to `-` to read from stdin. "
        "If not provided, a prompt will be shown."
    ),
    cls=VisibleOption,
)
@with_output_options
def command_set_username():
    """
    Store password in system keyring.
    """
    assert_keyring_available()

    raise NotImplementedError


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

from __future__ import annotations

import click
from pydantic_core import Url

from secrets_env.console.core import entrypoint, with_output_options


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
        if "://" in value:
            url = Url(value)
        elif "." in value:
            url = Url(f"https://{value}")
        else:
            raise click.BadParameter("Invalid host")
        return url.host


@entrypoint.group("set")
def group_set():
    """
    Manage value in per-user storage.

    This command group provides a way to store user-specific information in a
    secure and convenient manner. By storing values in a per-user configuration,
    you can avoid the need to re-enter sensitive information each time you run
    secrets.env.
    """


@group_set.command("username")
@click.option(
    "-t",
    "--target",
    type=HostParam(),
    required=True,
    help="Specify target host name for which the username will be used.",
    cls=VisibleOption,
)
@click.option(
    "-v",
    "--value",
    help=(
        "Specify the username value to store. "
        "Set to `-` to read from stdin. "
        "If not provided, a prompt will be shown."
    ),
    cls=VisibleOption,
)
@with_output_options
def command_set_username(target: str, value: str | None):
    """
    Store username in user configuration file.
    """
    raise NotImplementedError


@group_set.command("password")
@with_output_options
def command_set_username():
    """
    Store password in system keyring.
    """
    raise NotImplementedError

from __future__ import annotations

import json
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
    # get value
    if value == "-":
        value = click.get_text_stream("stdin").readline().rstrip("\r\n")
    if not value:
        value = secrets_env.utils.prompt("Username")
    if not value:
        raise click.UsageError("Value (username) is required.")

    set_username(target, value)


def set_username(host: str, value: str) -> None:
    """
    Store username in user configuration file.
    """
    # read config
    config_path = secrets_env.config.find_user_config_file()

    try:
        config = secrets_env.config.read_json_file(config_path) or {}
        logger.debug("Read user config from %s", config_path)
    except FileNotFoundError:
        config = {}

    # update config
    host_config = config.setdefault(host, {})
    auth_config = host_config.setdefault("auth", {})
    auth_config["username"] = value

    # write config
    logger.debug("Write user config to %s", config_path)

    config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w") as fd:
        json.dump(config, fd, indent=2)

    logger.info("Set username for <data>%s</data> to <data>%s</data>", host, value)


@group_set.command("password")
@with_output_options
def command_set_username():
    """
    Store password in system keyring.
    """
    raise NotImplementedError

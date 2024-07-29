from __future__ import annotations

import json
import logging
import typing

import click
from click.core import ParameterSource
from pydantic_core import Url

import secrets_env.config
import secrets_env.utils
from secrets_env.console.core import entrypoint, with_output_options

if typing.TYPE_CHECKING:
    from typing import Any, Mapping

    from click import Parameter


logger = logging.getLogger(__name__)


class VisibleOption(click.Option):
    """
    A :py:class:`click.Option` subclass that shows the option in the help text.
    """

    def get_usage_pieces(self, ctx: click.Context) -> list[str]:
        return [self.opts[-1], self.make_metavar()]


class StdinInputOption(VisibleOption):
    """
    When the value is `-`, read from stdin.
    """

    def consume_value(
        self, ctx: click.Context, opts: Mapping[Any, Parameter]
    ) -> tuple[Any, ParameterSource]:
        if opts.get(self.name) == "-":
            value = click.get_text_stream("stdin").readline().rstrip("\r\n")
            source = ParameterSource.ENVIRONMENT
            return value, source
        return super().consume_value(ctx, opts)


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


@group_set.command("username")
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
    help=(
        "Specify the username for the target host. "
        "Set to `-` to read from stdin. "
        "If not provided, a prompt will be shown."
    ),
    cls=StdinInputOption,
)
@click.option(
    "-d",
    "--delete",
    is_flag=True,
    help="Delete the stored username for the target host.",
)
@with_output_options
def command_set_username(target: Url, username: str | None, delete: bool):
    """
    Set or delete the username in user storage.

    This command saves the username in a user-specific configuration file,
    allowing it to be used for authenticating the user to the target host.

    Read username from stdin::

       $ echo demo_user | secrets.env set username -t https://example.com -u -

    When username is not provided, it will be prompted::

       $ secrets.env set username -t https://example.com/
    """
    if target.host is None:
        raise click.BadArgumentUsage("Host name not found in target URL")

    # read config
    config_path = secrets_env.config.find_user_config_file()

    try:
        config = secrets_env.config.read_json_file(config_path) or {}
        logger.debug("Read user config from %s", config_path)
    except FileNotFoundError:
        config = {}

    # update config
    if delete:
        remove_username(config, target.host)
    else:
        set_username(config, target.host, username)

    # write config
    logger.debug("Write user config to %s", config_path)

    config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w") as fd:
        json.dump(config, fd, indent=2)

    logger.info("Username for <data>%s</data> is updated", target.host)


def set_username(config: dict, host: str, username: str | None):
    if username is None:
        username = secrets_env.utils.prompt("Username")
    if username is None:
        raise click.BadArgumentUsage("Username is required")

    host_config = config.setdefault(host, {})
    auth_config = host_config.setdefault("auth", {})
    auth_config["username"] = username


def remove_username(config: dict, host: str):
    host_config = config.get(host, {})
    auth_config = host_config.get("auth", {})
    if "username" in auth_config:
        del auth_config["username"]


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
    cls=StdinInputOption,
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
    Save or delete the password in user storage.

    This command saves the password in the user's keyring, allowing it to be
    used for authenticating the user to the target host.

    Read password from stdin::

       $ echo P@ssw0rd | secrets.env set password -t https://example.com -u demo_user -p -

    When password is not provided, it will be prompted::

       $ secrets.env set password -t https://example.com -u demo_user
    """
    assert_keyring_available()

    key = secrets_env.utils.create_keyring_login_key(target, username)

    if delete:
        return remove_password(key)
    else:
        return set_password(key, password)


def set_password(key: str, password: str | None):
    import keyring
    import keyring.errors

    if password is None:
        password = secrets_env.utils.prompt("Password", hide_input=True)
    if password is None:
        raise click.BadArgumentUsage("Password is required")

    try:
        keyring.set_password("secrets.env", key, password)
    except keyring.errors.PasswordSetError:
        logger.error("Failed to save password")
        raise click.Abort from None

    logger.info("Password saved")


def remove_password(key: str):
    import keyring
    import keyring.errors

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

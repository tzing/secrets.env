import sys
import typing
from typing import List, Optional

import click

from secrets_env.click import entrypoint

if typing.TYPE_CHECKING:
    from click.shell_completion import CompletionItem


class _CredentialNameParamType(click.ParamType):
    name = "name"

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ) -> List["CompletionItem"]:
        from click.shell_completion import CompletionItem

        candidates = [
            *self.get_email_from_git(),
        ]

        suggestion = []
        for candidate in candidates:
            if candidate.startswith(incomplete):
                suggestion.append(CompletionItem(candidate))

        return suggestion

    @staticmethod
    def get_email_from_git():
        import subprocess

        rv = subprocess.run(["git", "config", "user.email"], stdout=subprocess.PIPE)
        if rv.returncode == 0:
            yield rv.stdout.rstrip().decode()


CredentialNameParamType = _CredentialNameParamType()


@entrypoint.group("keyring")
def group():
    """Manage credential using system keyring service."""


@group.command()
def status():
    """Check if keyring is available."""
    if not is_keyring_available():
        sys.exit(128)
    click.echo("ok")


@group.command()
@click.option(
    "-H", "--host", required=True, help="Specify the host for this credential set."
)
@click.option("-t", "--token", help="Token to be stored.")
@click.option("-u", "--user", type=CredentialNameParamType, help="Username.")
@click.option("-p", "--password", help="Password. This app will prompt for input.")
def set(host: str, token: str, user: str, password: str):
    """Store credential in system keyring.

    You must specify exactly one of the following options: '-t' / '--token' or
    '-u' / '--user'. These options are mutually exclusive.
    """
    # check input
    if not token and not user:
        raise click.UsageError("Missing option '-t' / '--token' or '-u' / '--user'.")
    elif token and user:
        raise click.UsageError(
            "Option '-t' / '--token' and '-u' / '--user' are mutually exclusive."
        )
    elif user:
        if not password:
            password = click.prompt("Password", hide_input=True)
        if not password:
            raise click.UsageError("Missing password (option '-p' / '--password').")

    # check keyring
    if not is_keyring_available():
        sys.exit(128)

    # save
    from secrets_env.utils import create_keyring_login_key, create_keyring_token_key

    if token:
        key = create_keyring_token_key(host)
        value = token
    else:
        key = create_keyring_login_key(host, user)
        value = password

    import keyring
    import keyring.errors

    try:
        keyring.set_password("secrets.env", key, value)
    except keyring.errors.PasswordSetError:
        click.secho("Failed to set password", fg="red", err=True)
        sys.exit(1)

    click.echo("ok")


def is_keyring_available() -> bool:
    try:
        import keyring
        import keyring.backends.fail
    except ImportError:
        click.echo(
            "Dependency `keyring` not found. "
            "Please install secrets.env with extras `[keyring]`.",
            file=sys.stderr,
        )
        return False

    if isinstance(keyring.get_keyring(), keyring.backends.fail.Keyring):
        click.echo("Keyring service is not available", file=sys.stderr)
        return False

    return True

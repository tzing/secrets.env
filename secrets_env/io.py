import os
import sys
from typing import Any, Optional, Union

import click
import keyring
import keyring.errors


def get_env_var(*names: str) -> Optional[str]:
    """Get value from (any candidate) environment variable."""
    for name in names:
        if var := os.getenv(name):
            return var
    return None


def prompt(
    text: str,
    default: Optional[Any] = None,
    hide_input: bool = False,
    type: Optional[Union["click.types.ParamType", Any]] = None,
    show_default: bool = True,
) -> Optional[Any]:
    """Wrapped `click.prompt` function. Shows the prompt when this feature is
    not disabled.

    Parameters
    ----------
    text : str
        The text to show for the prompt.
    default : Optional[Any]
        The default value to use if no input happens. If this is not given it
        will prompt until it's aborted.
    hide_input : bool
        If this is set to true then the input value will be hidden.
    type : Optional[Union[click.types.ParamType, Any]]
        The type to use to check the value against.
    show_default : bool
        Shows or hides the default value in the prompt.
    """
    # skip prompt if the env var is set
    env = os.getenv("SECRETS_ENV_NO_PROMPT", "FALSE")
    if env.upper() in ("TRUE", "T", "YES", "Y", "1"):
        return None

    try:
        return click.prompt(
            text=text,
            default=default,
            hide_input=hide_input,
            type=type,
            show_default=show_default,
        )
    except click.Abort:
        sys.stdout.write(os.linesep)
        return None


def read_keyring(name: str) -> Optional[str]:
    """Wrapped `keyring.get_password`. Do not raise error when there is no
    keyring backend enabled."""
    try:
        return keyring.get_password("secrets.env", name)
    except keyring.errors.NoKeyringError:
        return None

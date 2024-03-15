"""Utility collection."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import typing
from pathlib import Path
from typing import overload

if typing.TYPE_CHECKING:
    from typing import Any, Literal, TypeVar

    import click
    import httpx
    import pydantic_core

    T = TypeVar("T")
    TL_True = Literal[True]
    TL_False = Literal[False]

logger = logging.getLogger(__name__)

_ansi_re = re.compile(r"\033\[[;?0-9]*[a-zA-Z]")


@overload
def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: type[T],
    cast: bool,
    default: T,
) -> tuple[T, TL_True] | tuple[T, TL_False]: ...


@overload
def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: type[T],
    cast: bool,
) -> tuple[T, TL_True] | tuple[Literal[None], TL_False]: ...


def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: type[T],
    cast: bool,
    default: T | None = None,
) -> tuple[T, TL_True] | tuple[T | None, TL_False]:
    """Check if the given value is the expected type, fallback to default value
    and report errors on failed.

    This is a helper function to be used for config parsing. You may prefer
    :py:func:`ensure_dict`, :py:func:`ensure_path` or :py:func:`ensure_str`,
    which offers a simpler solution for the same purpose.

    Parameters
    ----------
    value_name : str
        Value name to be used on error reporting.
    value
        Value to be checked.
    type_name : str
        Name of expected type(s) to be used on error reporting.
    expect_type
        Type(s) could be used in :py:func:`isinstance`.
    cast : bool
        Try to cast ``value`` to ``expect_type`` when :py:func:`isinstance` failed.
    default
        Default value when all checks failed.

    Returns
    -------
    ok : bool
        Type check success
    value
        Value that matches expect type
    """
    # returns ok if already the desired type
    if isinstance(value, expect_type):
        return value, True

    # try type casting
    if cast:
        try:
            return expect_type(value), True
        except Exception:
            ...

    # show warning and returns default value
    logger.warning(
        "Expect <mark>%s</mark> type for config <mark>%s</mark>, "
        "got <data>%s</data> (<mark>%s</mark> type)",
        type_name,
        value_name,
        trimmed_str(value),
        type(value).__name__,
    )
    return default, False


def ensure_dict(name: str, d: Any) -> tuple[dict, bool]:
    """Ensure the input is :py:class:`dict`. Read :py:func:`ensure_type` for
    more details."""
    return ensure_type(name, d, "dict", dict, False, {})


def ensure_path(
    name: str, p: Any, is_file: bool = True
) -> tuple[Path, TL_True] | tuple[None, TL_False]:
    """Ensure the input is :py:class:`pathlib.Path`. Read :py:func:`ensure_type`
    for more details."""
    path: Path | None
    path, _ = ensure_type(name, p, "path", Path, True)
    if not path:
        return None, False

    if is_file and not path.is_file():
        logger.warning(
            "Expect valid path for config <mark>%s</mark>: "
            "file <data>%s</data> not exists",
            name,
            path,
        )
        return None, False

    return path, True


def ensure_str(name: str, s: Any) -> tuple[str, TL_True] | tuple[None, TL_False]:
    """Ensure the input is :py:class:`str`. Read :py:func:`ensure_type` for
    more details."""
    return ensure_type(name, s, "str", str, False)


def get_env_var(*names: str) -> str | None:
    """Get value from environment variable."""
    for name in names:
        if var := os.getenv(name.upper()):
            return var
        if var := os.getenv(name.lower()):
            return var
    return None


def get_bool_from_env_var(*names: str, default: bool = False) -> bool:
    """Get boolean value from environment variable. It returns :py:obj:`True`
    when value is any of ``TRUE``, ``T``, ``YES``, ``Y`` or ``1`` case insensitive,
    or :py:obj:`False` otherwise. When variable is not set, it returns default.
    """
    env = get_env_var(*names)
    if not env:
        return default
    return env.upper() in ("TRUE", "T", "YES", "Y", "1")


def get_httpx_error_reason(e: httpx.HTTPError):
    """Returns a reason for those errors that should not breaks the program.
    This is a helper function to be used in ``expect`` clause."""
    import httpx

    logger.debug("httpx error occurs. Type= %s", type(e).__name__, exc_info=True)

    if isinstance(e, httpx.ProxyError):
        return "proxy error"
    elif isinstance(e, httpx.TransportError):
        return "connection error"

    return None


def log_httpx_response(logger_: logging.Logger, resp: httpx.Response):
    """Print :py:class:`httpx.Response` to debug log."""
    import httpx

    logger_.debug(
        "URL= %s; Status= %d (%s); Raw response= %s",
        resp.url,
        resp.status_code,
        resp.reason_phrase
        or httpx.codes.get_reason_phrase(resp.status_code)
        or "Unknown",
        resp.text,
    )


def prompt(
    text: str,
    default: Any | None = None,
    hide_input: bool = False,
    type: click.types.ParamType | type | None = None,
    show_default: bool = True,
) -> Any:
    """Wrap :py:func:`click.prompt`, shows the prompt when this feature is not disabled.

    Parameters
    ----------
    text : str
        The text to show for the prompt.
    default : Any | None
        The default value to use if no input happens. If this is not given it
        will prompt until it's aborted.
    hide_input : bool
        If this is set to true then the input value will be hidden.
    type : click.types.ParamType | Any | None
        The type to use to check the value against.
    show_default : bool
        Shows or hides the default value in the prompt.
    """
    import click

    # skip prompt if the env var is set
    if get_bool_from_env_var("SECRETS_ENV_NO_PROMPT"):
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


def read_keyring(key: str) -> str | None:
    """Wrap :py:func:`keyring.get_password` and capture error when keyring is
    not available."""
    # skip prompt if the env var is set
    if get_bool_from_env_var("SECRETS_ENV_NO_KEYRING"):
        return None

    # load optional dependency
    try:
        import keyring
        import keyring.errors
    except ImportError:
        return None

    # read value
    try:
        value = keyring.get_password("secrets.env", key)
    except keyring.errors.NoKeyringError:
        value = None

    logger.debug(
        "Read keyring for %s: %s", key, "success" if value is not None else "failed"
    )
    return value


def create_keyring_login_key(url: pydantic_core.Url, user: str) -> str:
    """Build key for storing login credentials in keyring."""
    return json.dumps({"host": url.host, "type": "login", "user": user.casefold()})


def create_keyring_token_key(url: pydantic_core.Url):
    """Build key for storing token in keyring."""
    return json.dumps({"host": url.host, "type": "token"})


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return _ansi_re.sub("", value)


def trimmed_str(o: Any) -> str:
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

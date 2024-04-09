"""Utility collection."""

from __future__ import annotations

import collections
import json
import logging
import os
import re
import sys
import threading
import typing
from typing import TypeVar, overload

if typing.TYPE_CHECKING:
    import click
    import httpx
    import pydantic_core

    T = TypeVar("T")

logger = logging.getLogger(__name__)

_ansi_re = re.compile(r"\033\[[;?0-9]*[a-zA-Z]")


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
    default: T | None = None,
    hide_input: bool = False,
    type: click.types.ParamType | type[T] | None = None,
    show_default: bool = True,
) -> T | None:
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
    type : click.types.ParamType | type | None
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


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return _ansi_re.sub("", value)


TK = TypeVar("TK")
TV = TypeVar("TV")


class LruDict(collections.OrderedDict[TK, TV]):
    """A dict that implements LRU cache"""

    def __init__(self, max_size=128):
        super().__init__()
        self.max_size = max_size
        self._lock = threading.RLock()

    def __getitem__(self, key: TK) -> TV:
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key: TK, value: TV) -> None:
        with self._lock:
            super().__setitem__(key, value)
            self.move_to_end(key)
            if len(self) > self.max_size:
                first = next(iter(self))
                self.__delitem__(first)

    def __delitem__(self, key: TK) -> None:
        with self._lock:
            super().__delitem__(key)

    @overload
    def get(self, key: TK) -> TV | None: ...
    @overload
    def get(self, key: TK, default: T) -> TV | T: ...

    def get(self, key: TK, default: TV | T | None = None) -> TV | T | None:
        try:
            return self[key]
        except KeyError:
            return default

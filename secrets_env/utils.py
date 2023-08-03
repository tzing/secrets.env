"""Utility collection."""
import logging
import os
import re
import sys
import typing
from pathlib import Path
from typing import Any, Literal, Optional, Tuple, Type, TypeVar, Union, overload

if typing.TYPE_CHECKING:
    import click
    import httpx

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
    expect_type: Type[T],
    cast: bool,
    default: T,
) -> Union[Tuple[T, TL_True], Tuple[T, TL_False]]:
    ...  # pragma: no cover


@overload
def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: Type[T],
    cast: bool,
) -> Union[Tuple[T, TL_True], Tuple[Literal[None], TL_False]]:
    ...  # pragma: no cover


def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: Type[T],
    cast: bool,
    default: Optional[T] = None,
) -> Union[Tuple[T, TL_True], Tuple[Optional[T], TL_False]]:
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


def ensure_dict(name: str, d: Any) -> Tuple[dict, bool]:
    """Ensure the input is :py:class:`dict`. Read :py:func:`ensure_type` for
    more details."""
    return ensure_type(name, d, "dict", dict, False, {})


def ensure_path(
    name: str, p: Any, is_file: bool = True
) -> Union[Tuple[Path, TL_True], Tuple[None, TL_False]]:
    """Ensure the input is :py:class:`pathlib.Path`. Read :py:func:`ensure_type`
    for more details."""
    path: Optional[Path]
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


def ensure_str(name: str, s: Any) -> Union[Tuple[str, TL_True], Tuple[None, TL_False]]:
    """Ensure the input is :py:class:`str`. Read :py:func:`ensure_type` for
    more details."""
    return ensure_type(name, s, "str", str, False)


def get_env_var(*names: str) -> Optional[str]:
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


def get_httpx_error_reason(e: "httpx.HTTPError"):
    """Returns a reason for those errors that should not breaks the program.
    This is a helper function to be used in ``expect`` clause."""
    import httpx

    logger.debug("httpx error occurs. Type= %s", type(e).__name__, exc_info=True)

    if isinstance(e, httpx.ProxyError):
        return "proxy error"
    elif isinstance(e, httpx.TransportError):
        return "connection error"

    return None


def log_httpx_response(logger_: logging.Logger, resp: "httpx.Response"):
    """Print :py:class:`httpx.Response` to debug log."""
    import http

    try:
        code_enum = http.HTTPStatus(resp.status_code)
        code_name = code_enum.name
    except ValueError:
        code_name = "unknown"

    logger_.debug(
        "URL= %s; Status= %d (%s); Raw response= %s",
        resp.url,
        resp.status_code,
        code_name,
        resp.text,
    )


def prompt(
    text: str,
    default: Optional[Any] = None,
    hide_input: bool = False,
    type: Optional[Union["click.types.ParamType", Any]] = None,
    show_default: bool = True,
) -> Optional[Any]:
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


def read_keyring(key: str) -> Optional[str]:
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


def create_keyring_login_key(host: str, user: str) -> str:
    """Build key for storing login credentials in keyring."""
    import json

    return json.dumps(
        {"host": extract_http_host(host), "type": "login", "user": user.casefold()}
    )


def create_keyring_token_key(host: str):
    """Build key for storing token in keyring."""
    import json

    return json.dumps({"host": extract_http_host(host), "type": "token"})


def extract_http_host(url: str) -> str:
    """Extract hostname from given URL."""
    if "://" not in url:
        return extract_http_host(f"http://{url}")

    import urllib.parse

    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"Invalid scheme: {u.scheme}")

    hostname = typing.cast(str, u.hostname)
    return hostname.casefold()


def removeprefix(s: str, prefix: str):
    # str.removeprefix is only available after python 3.9
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s


def strip_ansi(value: str) -> str:
    """Strip ANSI escape codes from the string."""
    return _ansi_re.sub("", value)


def trimmed_str(o: Any) -> str:
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

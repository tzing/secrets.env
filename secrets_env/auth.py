import abc
import importlib
import logging
import os
import pathlib
import sys
import typing
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

import keyring
import keyring.errors

if typing.TYPE_CHECKING:
    import click
    import hvac


logger = logging.getLogger(__name__)


def get_password(name: str) -> Optional[str]:
    """Wrapped `keyring.get_password`. Do not raise error when there is no
    keyring backend enabled."""
    try:
        return keyring.get_password("secrets.env", name)
    except keyring.errors.NoKeyringError:
        return None


def prompt(
    text: str,
    default: Optional[Any] = None,
    hide_input: bool = False,
    type: Optional[Union["click.types.ParamType", Any]] = None,
    show_default: bool = True,
) -> Optional[Any]:
    """Wrapped `click.prompt` function. Only shows the prompt when click is
    installed and this feature is not disabled.

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
    # skip prompt if click is not installed
    try:
        click = importlib.import_module("click")
    except ImportError:
        return None

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


class Auth(abc.ABC):
    """Base class for authentication schemes."""

    @abc.abstractclassmethod
    def method(cls) -> str:
        """Returns authentication name."""

    @abc.abstractmethod
    def apply(self, client: "hvac.Client") -> None:
        """Provide the identity information to the client."""

    @abc.abstractclassmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        """Initialize an instance of this class using the provided config data
        or internally load the secrets from the system."""


@dataclass(frozen=True)
class TokenAuth(Auth):
    """Token-based authentication."""

    token: str
    """Authentication token."""

    def __init__(self, token: str) -> None:
        """
        Parameters
        ----------
        token : str
            Authentication token.
        """
        if not isinstance(token, str):
            raise TypeError("Expect str for token, got {}", type(token).__name__)
        object.__setattr__(self, "token", token)

    @classmethod
    def method(cls) -> str:
        return "token"

    def apply(self, client: "hvac.Client"):
        client.token = self.token

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        token = os.getenv("SECRETS_ENV_TOKEN")
        if not token:
            token = os.getenv("VAULT_TOKEN")
        if not token:
            token = cls._load_from_home()
        if not token:
            token = get_password("token/:token")
        if not isinstance(token, str):
            logger.error(
                "Missing auth information: token. "
                "Environment variable `SECRETS_ENV_TOKEN` not found."
            )
            return None
        return cls(token)

    @classmethod
    def _load_from_home(cls) -> Optional[str]:
        # vault places the token on the disk
        # https://www.vaultproject.io/docs/commands/token-helper
        file_ = pathlib.Path.home() / ".vault-token"
        if not file_.is_file():
            return None

        with file_.open("r", encoding="utf-8") as fd:
            # (don't think the token could be so long)
            return fd.read(256).strip()


@dataclass(frozen=True)
class UserPasswordAuth(Auth):
    """Username and password based authentication."""

    username: str
    """User name."""

    password: str = field(repr=False)
    """Password."""

    def __init__(self, username: str, password: str) -> None:
        if not isinstance(username, str):
            raise TypeError("Expect str for username, got {}", type(username).__name__)
        if not isinstance(password, str):
            raise TypeError("Expect str for password, got {}", type(password).__name__)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        method = cls.method()

        username = os.getenv("SECRETS_ENV_USERNAME")
        if not username:
            username = data.get("username")
        if not username:
            username = get_password(f"{method}/:username")
        if not username:
            username = prompt(f"Username for {method} auth")
        if not isinstance(username, str):
            logger.error(
                "Missing username for %s auth. Stop loading secrets.",
                method,
            )
            return None

        password = os.getenv("SECRETS_ENV_PASSWORD")
        if not password:
            password = get_password(f"{method}/{username}")
        if not password:
            password = prompt("Password", hide_input=True)
        if not isinstance(password, str):
            logger.error(
                "Missing password for %s auth. Stop loading secrets.",
                method,
            )
            return None

        return cls(username, password)


@dataclass(frozen=True)
class OktaAuth(UserPasswordAuth):
    """Okta authentication."""

    @classmethod
    def method(cls):
        return "okta"

    def __init__(self, username: str, password: str) -> None:
        """
        Parameters
        ----------
        username : str
            User name to login to Okta.
        password : str
            Password to login to Okta.
        """
        super().__init__(username, password)

    def apply(self, client: "hvac.Client"):
        logger.info(
            "Login to <mark>Okta</mark> with user <data>%s</data>. "
            "Waiting for 2FA proceeded...",
            self.username,
        )

        # Okta 2FA got triggerred within this api call
        client.auth.okta.login(
            username=self.username,
            password=self.password,
        )

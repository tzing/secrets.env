import abc
import logging
import os
import typing
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import keyring

if typing.TYPE_CHECKING:
    import hvac


logger = logging.getLogger(__name__)

KEYRING_SYSTEM_NAME = "secrets.env"


class Auth(abc.ABC):
    """Base class for authentication schemes."""

    method: str
    """Authentication method."""

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
        object.__setattr__(self, "method", "token")
        object.__setattr__(self, "token", token)

    def apply(self, client: "hvac.Client"):
        client.token = self.token

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        token = os.getenv("VAULT_TOKEN")
        if not token:
            token = keyring.get_password(KEYRING_SYSTEM_NAME, "token/:token")
        if not isinstance(token, str):
            logger.error(
                "Missing auth information: token. "
                "Environment variable `VAULT_TOKEN` not found."
            )
            return None
        return cls(token)


@dataclass(frozen=True)
class OktaAuth(Auth):
    """Token-based authentication."""

    username: str
    """User name."""

    password: str = field(repr=False)
    """Password."""

    def __init__(self, username: str, password: str) -> None:
        """
        Parameters
        ----------
        username : str
            User name to login to Okta.
        password : str
            Password to login to Okta.
        """
        if not isinstance(username, str):
            raise TypeError("Expect str for username, got {}", type(username).__name__)
        if not isinstance(password, str):
            raise TypeError("Expect str for password, got {}", type(password).__name__)
        object.__setattr__(self, "method", "okta")
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)

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

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        username = data.get("username")
        if not username:
            username = os.getenv("VAULT_USERNAME")
        if not username:
            username = keyring.get_password(KEYRING_SYSTEM_NAME, "okta/:username")
        if not isinstance(username, str):
            logger.error(
                "Missing auth information: username. Neither key 'username' in "
                "config nor environment variable `VAULT_USERNAME` is found."
            )
            return None

        password = os.getenv("VAULT_PASSWORD")
        if not password:
            password = keyring.get_password(KEYRING_SYSTEM_NAME, f"okta/{username}")
        if not isinstance(password, str):
            logger.error(
                "Missing auth information: password. "
                "Environment variable `VAULT_PASSWORD` not found."
            )
            return None

        return cls(username, password)

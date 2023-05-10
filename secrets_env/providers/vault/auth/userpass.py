import abc
import logging
import typing
import urllib.parse
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Dict, Optional

from secrets_env.exceptions import TypeError
from secrets_env.io import get_env_var, prompt, read_keyring

from .base import Auth

if typing.TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UserPasswordAuth(Auth):
    """Username and password based authentication."""

    @classmethod
    @abc.abstractmethod
    def path(cls) -> str:
        """Returns method name used by Vault."""
        raise NotImplementedError()

    _TIMEOUT = None

    username: str
    """User name."""

    password: str = field(repr=False)
    """Password."""

    def __init__(self, username: str, password: str) -> None:
        if not isinstance(username, str):
            raise TypeError("username", str, username)
        if not isinstance(password, str):
            raise TypeError("password", str, password)
        object.__setattr__(self, "username", username)
        object.__setattr__(self, "password", password)

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional["UserPasswordAuth"]:
        username = cls._load_username(data)
        if not isinstance(username, str) or not username:
            logger.error(
                "Missing username for %s auth.",
                cls.method(),
            )
            return None

        password = cls._load_password(username)
        if not isinstance(password, str) or not password:
            logger.error(
                "Missing password for %s auth.",
                cls.method(),
            )
            return None

        return cls(username, password)

    @classmethod
    def _load_username(cls, data: Dict[str, Any]) -> Optional[str]:
        username = get_env_var("SECRETS_ENV_USERNAME")
        if username:
            logger.debug("Found username from environment variable.")
            return username

        username = data.get("username")
        if username:
            return username

        return prompt(f"Username for {cls.method()} auth")

    @classmethod
    def _load_password(cls, username: str) -> Optional[str]:
        password = get_env_var("SECRETS_ENV_PASSWORD")
        if password:
            logger.debug("Found password from environment variable.")
            return password

        password = read_keyring(f"{cls.path()}/{username}")
        if password:
            logger.debug("Found password in keyring")
            return password

        return prompt(f"Password for {username}", hide_input=True)

    def login(self, client: "httpx.Client") -> Optional[str]:
        # build request
        username = urllib.parse.quote(self.username)
        resp = client.post(
            f"/v1/auth/{self.path()}/login/{username}",
            json={
                "username": self.username,
                "password": self.password,
            },
            timeout=self._TIMEOUT,
        )

        # check response
        if resp.status_code != HTTPStatus.OK:
            logger.error("Failed to login with %s method", self.method())
            logger.debug(
                "Login failed. URL= %s, Code= %d. Msg= %s",
                resp.url,
                resp.status_code,
                resp.text,
            )
            return

        return resp.json()["auth"]["client_token"]


@dataclass(frozen=True)
class BasicAuth(UserPasswordAuth):
    """Login to Vault using user name and password."""

    @classmethod
    def method(cls):
        return "basic"

    @classmethod
    def path(cls):
        return "userpass"


@dataclass(frozen=True)
class LDAPAuth(UserPasswordAuth):
    """Login with LDAP credentials."""

    @classmethod
    def method(cls):
        return "LDAP"

    @classmethod
    def path(cls):
        return "ldap"


@dataclass(frozen=True)
class OktaAuth(UserPasswordAuth):
    """Okta authentication."""

    # Okta 2FA got triggerred within the api call, so needs a longer timeout
    _TIMEOUT = 60.0

    @classmethod
    def method(cls):
        return "Okta"

    @classmethod
    def path(cls):
        return "okta"


class RADIUSAuth(UserPasswordAuth):
    """RADIUS authentication with PAP authentication scheme."""

    @classmethod
    def method(cls):
        return "RADIUS"

    @classmethod
    def path(cls):
        return "radius"

import logging
import typing
import urllib.parse
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Dict, Optional

from secrets_env.auth.base import Auth
from secrets_env.exception import TypeError
from secrets_env.io import get_env_var, prompt, read_keyring

if typing.TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)


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
    def load(cls, data: Dict[str, Any]) -> Optional["UserPasswordAuth"]:
        username = cls._load_username(data)
        if not isinstance(username, str) or not username:
            logger.error(
                "Missing username for %s auth. Stop loading secrets.",
                cls.method(),
            )
            return None

        password = cls._load_password(username)
        if not isinstance(password, str) or not password:
            logger.error(
                "Missing password for %s auth. Stop loading secrets.",
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

        method = cls.method()
        username = read_keyring(f"{method}/:username")
        if username:
            logger.debug("Found username from keyring")
            return username

        return prompt(f"Username for {method} auth")

    @classmethod
    def _load_password(cls, username: str) -> Optional[str]:
        password = get_env_var("SECRETS_ENV_PASSWORD")
        if password:
            logger.debug("Found password from environment variable.")
            return password

        method = cls.method()
        password = read_keyring(f"{method}/{username}")
        if password:
            logger.debug("Found password from keyring")
            return password

        return prompt("Password", hide_input=True)


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

    def login(self, client: "httpx.Client") -> str:
        logger.info(
            "<!important>Login to <mark>Okta</mark> with user <data>%s</data>. "
            "Waiting for 2FA proceeded...",
            self.username,
        )

        # Okta 2FA got triggerred within this api call
        username = urllib.parse.quote(self.username)
        resp = client.post(
            f"/v1/auth/okta/login/{username}",
            json={
                "username": self.username,
                "password": self.password,
            },
        )

        if resp.status_code != HTTPStatus.OK:
            logger.error("Failed to login Okta")
            logger.debug(
                "Okta login failed. Code= %d. Msg= %s", resp.status_code, resp.text
            )
            return

        return resp.json()["auth"]["client_token"]

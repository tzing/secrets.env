from __future__ import annotations

import logging
import urllib.parse
from typing import TYPE_CHECKING, ClassVar, cast

from pydantic import PrivateAttr, SecretStr

from secrets_env.config import load_user_config
from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.utils import (
    create_keyring_login_key,
    get_env_var,
    prompt,
    read_keyring,
)

if TYPE_CHECKING:
    from typing import Self

    import httpx
    from pydantic import AnyUrl

logger = logging.getLogger(__name__)


class UserPasswordAuth(Auth):
    """Username and password based authentication."""

    vault_name: ClassVar[str]
    """Name used in Vault request."""

    username: str
    """User name."""

    password: SecretStr
    """Password."""

    _timeout: float | None = PrivateAttr(None)
    """Request timeout."""

    @classmethod
    def create(cls, url: AnyUrl, config: dict) -> Self:
        username = get_username(url, config)
        if not username:
            raise ValueError(f"Missing username for {cls.method} auth")

        password = get_password(url, username)
        if not password:
            raise ValueError(f"Missing password for {cls.method} auth")

        return cls(
            username=username,
            password=cast(SecretStr, password),
        )

    def login(self, client: httpx.Client) -> str:
        username = urllib.parse.quote(self.username)
        resp = client.post(
            f"/v1/auth/{self.vault_name}/login/{username}",
            json={
                "username": self.username,
                "password": self.password.get_secret_value(),
            },
            timeout=self._timeout,
        )

        if not resp.is_success:
            logger.debug(
                "Login failed. URL= %s, Code= %d. Msg= %s",
                resp.url,
                resp.status_code,
                resp.text,
            )
            raise AuthenticationError(f"Failed to login with {self.method} method")

        return resp.json()["auth"]["client_token"]


def get_username(url: AnyUrl, config: dict) -> str | None:
    if username := get_env_var("SECRETS_ENV_USERNAME"):
        logger.debug("Found username from environment variable.")
        return username

    if username := config.get("username"):
        return username

    user_config = load_user_config(url)
    if username := user_config.get("auth", {}).get("username"):
        logger.debug("Found username in user config.")
        return username

    return prompt(f"Username for {url.host}")


def get_password(url: AnyUrl, username: str) -> str | None:
    if password := get_env_var("SECRETS_ENV_PASSWORD"):
        logger.debug("Found password from environment variable.")
        return password

    if password := read_keyring(create_keyring_login_key(url, username)):
        logger.debug("Found password in keyring")
        return password

    return prompt(f"Password for {username}", hide_input=True)


class LdapAuth(UserPasswordAuth):
    """Login with LDAP credentials."""

    method = "LDAP"
    vault_name = "ldap"


class OktaAuth(UserPasswordAuth):
    """Okta authentication."""

    method = "Okta"
    vault_name = "okta"

    # Okta 2FA got triggerred within the api call, so needs a longer timeout
    _timeout: float | None = PrivateAttr(60.0)


class RadiusAuth(UserPasswordAuth):
    """RADIUS authentication with PAP authentication scheme."""

    method = "RADIUS"
    vault_name = "radius"


class UserPassAuth(UserPasswordAuth):
    """Login to Vault using user name and password."""

    method = "Userpass"
    vault_name = "userpass"

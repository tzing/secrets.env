from __future__ import annotations

import logging
import urllib.parse
from typing import TYPE_CHECKING, ClassVar, Optional, cast

from pydantic import PrivateAttr, SecretStr

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

OptionalFloat = Optional[float]  # workaround for UP007; remove after py 3.10

logger = logging.getLogger(__name__)


class UserPasswordAuth(Auth):
    """Username and password based authentication."""

    vault_name: ClassVar[str]
    """Name used in Vault request."""

    username: str
    """User name."""

    password: SecretStr
    """Password."""

    _timeout: ClassVar[OptionalFloat] = PrivateAttr(None)
    """Request timeout."""

    @classmethod
    def create(cls, url: str, config: dict) -> Self:
        username = cls._get_username(config)
        if not username:
            raise ValueError(f"Missing username for {cls.method} auth")

        password = cls._get_password(url, username)
        if not password:
            raise ValueError(f"Missing password for {cls.method} auth")

        return cls(
            username=username,
            password=cast(SecretStr, password),
        )

    @classmethod
    def _get_username(cls, config: dict) -> str | None:
        if username := get_env_var("SECRETS_ENV_USERNAME"):
            logger.debug("Found username from environment variable.")
            return username

        if username := config.get("username"):
            return username

        return prompt(f"Username for {cls.method} auth")

    @classmethod
    def _get_password(cls, url: str, username: str) -> str | None:
        if password := get_env_var("SECRETS_ENV_PASSWORD"):
            logger.debug("Found password from environment variable.")
            return password

        if password := read_keyring(create_keyring_login_key(url, username)):
            logger.debug("Found password in keyring")
            return password

        return prompt(f"Password for {username}", hide_input=True)

    def login(self, client: httpx.Client) -> str | None:
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
            logger.error("Failed to login with %s method", self.method)
            logger.debug(
                "Login failed. URL= %s, Code= %d. Msg= %s",
                resp.url,
                resp.status_code,
                resp.text,
            )
            return

        return resp.json()["auth"]["client_token"]


class BasicAuth(UserPasswordAuth):
    """Login to Vault using user name and password."""

    method = "basic"
    vault_name = "userpass"


class LDAPAuth(UserPasswordAuth):
    """Login with LDAP credentials."""

    method = "LDAP"
    vault_name = "ldap"


class OktaAuth(UserPasswordAuth):
    """Okta authentication."""

    method = "Okta"
    vault_name = "okta"

    # Okta 2FA got triggerred within the api call, so needs a longer timeout
    _timeout = PrivateAttr(60.0)


class RADIUSAuth(UserPasswordAuth):
    """RADIUS authentication with PAP authentication scheme."""

    method = "RADIUS"
    vault_name = "radius"

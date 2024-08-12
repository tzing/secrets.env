from __future__ import annotations

import logging
from typing import TYPE_CHECKING, ClassVar

from pydantic import SecretStr  # noqa: TCH002

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.base import Auth

if TYPE_CHECKING:
    import httpx
    from pydantic_core import Url
    from typing_extensions import Self

logger = logging.getLogger(__name__)


class JwtAuth(Auth):
    """
    JSON Web Token (JWT).
    """

    method = "JWT"

    request_path: ClassVar[str] = "/v1/auth/jwt/login"

    token: SecretStr
    """Json Web Token"""

    role: str | None
    """Role."""

    @classmethod
    def create(cls, url: Url, config: dict) -> Self:
        raise NotImplementedError

    def login(self, client: httpx.Client) -> str:
        payload = {"jwt": self.token.get_secret_value()}
        if self.role:
            payload["role"] = self.role

        resp = client.post(self.request_path, json=payload)
        if not resp.is_success:
            logger.debug(
                "Authentication failed. URL= %s, Code= %d. Msg= %s",
                resp.url,
                resp.status_code,
                resp.text,
            )
            raise AuthenticationError(
                f"Failed to authenticate using {self.method} method"
            )

        return resp.json()["auth"]["client_token"]

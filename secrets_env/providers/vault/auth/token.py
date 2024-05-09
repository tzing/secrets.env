from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

from pydantic import SecretStr

from secrets_env.providers.vault.auth.base import Auth
from secrets_env.utils import get_env_var

if TYPE_CHECKING:
    from typing import Any

    from pydantic_core import Url

logger = logging.getLogger(__name__)


class TokenAuth(Auth):
    """Token-based authentication."""

    method = "token"

    token: SecretStr
    """Authentication token.

    See also
    --------
    https://developer.hashicorp.com/vault/tutorials/tokens/tokens#token-prefix
    """

    @classmethod
    def create(cls, url: Url, config: dict) -> TokenAuth:
        # env var
        if token := get_env_var("SECRETS_ENV_TOKEN", "VAULT_TOKEN"):
            logger.debug("Found token from environment variable")
        token = cast(SecretStr, token)
        return cls(token=token)

    def login(self, client: Any) -> str:
        return self.token.get_secret_value()

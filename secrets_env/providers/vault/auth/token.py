from __future__ import annotations

import logging
import typing
from pathlib import Path
from typing import cast

from pydantic import SecretStr

from secrets_env.providers.vault.auth.base import Auth
from secrets_env.utils import create_keyring_token_key, get_env_var, read_keyring

if typing.TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


class TokenAuth(Auth):
    """Token-based authentication."""

    method: str = "token"

    token: SecretStr
    """Authentication token.

    See also
    --------
    https://developer.hashicorp.com/vault/tutorials/tokens/tokens#token-prefix
    """

    @classmethod
    def create(cls, url: str, config: dict) -> TokenAuth | None:
        # env var
        if token := get_env_var("SECRETS_ENV_TOKEN", "VAULT_TOKEN"):
            logger.debug("Found token from environment variable")
            token = cast(SecretStr, token)
            return cls(token=token)

        # token helper
        # https://www.vaultproject.io/docs/commands/token-helper
        helper_path = Path.home() / ".vault-token"
        if helper_path.is_file():
            logger.debug("Found token from token helper")
            with helper_path.open("r", encoding="utf-8") as fd:
                # don't think the token could be this long
                token = fd.read(256).strip()
            token = cast(SecretStr, token)
            return cls(token=token)

        # keyring
        if token := read_keyring(create_keyring_token_key(url)):
            logger.debug("Found token from keyring")
            token = cast(SecretStr, token)
            return cls(token=token)

    def login(self, client: Any) -> str:
        return self.token.get_secret_value()

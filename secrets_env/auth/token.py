import dataclasses
import logging
import typing
from pathlib import Path
from typing import Any, Dict, Optional

from secrets_env.auth.base import Auth
from secrets_env.exception import TypeError
from secrets_env.io import get_env_var, read_keyring

if typing.TYPE_CHECKING:
    import hvac

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
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
    def load(cls, data: Dict[str, Any]) -> Optional[Auth]:
        # env var
        token = get_env_var("SECRETS_ENV_TOKEN", "VAULT_TOKEN")
        if token:
            logger.debug("Found token from environment variable")
            return cls(token)

        # token helper
        # https://www.vaultproject.io/docs/commands/token-helper
        file_ = Path.home() / ".vault-token"
        if file_.is_file():
            with file_.open("r", encoding="utf-8") as fd:
                # don't think the token could be so long
                token = fd.read(256).strip()
            logger.debug("Found token from token helper")
            return cls(token)

        # keyring
        token = read_keyring("token/:token")
        if token:
            logger.debug("Found token from keyring")
            return cls(token)

        logger.error("Missing auth information: token. Stop loading secrets.")
        return None

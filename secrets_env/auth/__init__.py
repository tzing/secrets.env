import logging
from typing import Optional

from secrets_env.auth.base import Auth
from secrets_env.auth.token import TokenAuth
from secrets_env.auth.userpass import OktaAuth

logger = logging.getLogger(__name__)


def get_auth(name: str, data: dict) -> Optional[Auth]:
    """Factory for building Auth object."""
    name_ = name.lower()
    if name_ == "token":
        return TokenAuth.load(data)
    elif name_ == "okta":
        return OktaAuth.load(data)

    logger.error("Unknown auth method: <data>%s</data>", name)
    return None

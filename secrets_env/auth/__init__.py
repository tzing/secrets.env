import logging
from typing import Optional

from secrets_env.auth.base import Auth

logger = logging.getLogger(__name__)


def get_auth(name: str, data: dict) -> Optional[Auth]:
    """Factory for building Auth object."""
    name_ = name.lower()

    # fmt: off
    if name_ == "token":
        from secrets_env.auth.token import TokenAuth
        return TokenAuth.load(data)
    elif name_ == "okta":
        from secrets_env.auth.userpass import OktaAuth
        return OktaAuth.load(data)
    # fmt: on

    logger.error("Unknown auth method: <data>%s</data>", name)
    return None

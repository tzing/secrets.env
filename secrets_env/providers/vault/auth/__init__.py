import logging
from typing import Optional

from secrets_env.providers.vault.auth.base import Auth
from secrets_env.providers.vault.auth.base import Auth

logger = logging.getLogger(__name__)


def get_auth(name: str, data: dict) -> Optional[Auth]:
    """Factory for building Auth object."""
    name_ = name.lower()

    # fmt: off
    if name_ == "token":
        from secrets_env.providers.vault.auth.token import TokenAuth
        return TokenAuth.load(data)
    elif name_ == "basic":
        from secrets_env.providers.vault.auth.userpass import BasicAuth
        return BasicAuth.load(data)
    elif name_ == "ldap":
        from secrets_env.providers.vault.auth.userpass import LDAPAuth
        return LDAPAuth.load(data)
    elif name_ == "oidc":
        from secrets_env.providers.vault.auth.oidc import OpenIDConnectAuth
        return OpenIDConnectAuth.load(data)
    elif name_ == "okta":
        from secrets_env.providers.vault.auth.userpass import OktaAuth
        return OktaAuth.load(data)
    elif name_ == "radius":
        from secrets_env.providers.vault.auth.userpass import RADIUSAuth
        return RADIUSAuth.load(data)
    elif name_ == "null":
        from secrets_env.providers.vault.auth.null import NoAuth
        return NoAuth.load(data)
    # fmt: on

    logger.error("Unknown auth method: <data>%s</data>", name)
    return None

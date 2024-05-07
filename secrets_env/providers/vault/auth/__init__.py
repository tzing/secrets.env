from __future__ import annotations

__all__ = ["Auth", "create_auth_by_name"]

import logging
import typing

from secrets_env.providers.vault.auth.base import Auth

if typing.TYPE_CHECKING:
    from pydantic_core import Url


logger = logging.getLogger(__name__)


def create_auth_by_name(url: Url, config: dict) -> Auth:
    """
    Create an instance of the authentication class by the provided name.
    """
    logger.debug('Creating "%s" auth', config["method"])
    method: str = config["method"].lower()

    # fmt: off
    if method == "ldap":
        from secrets_env.providers.vault.auth.userpass import LDAPAuth
        return LDAPAuth.create(url, config)
    if method == "null":
        from secrets_env.providers.vault.auth.base import NoAuth
        return NoAuth.create(url, config)
    if method == "oidc":
        from secrets_env.providers.vault.auth.oidc import OpenIDConnectAuth
        return OpenIDConnectAuth.create(url, config)
    if method == "okta":
        from secrets_env.providers.vault.auth.userpass import OktaAuth
        return OktaAuth.create(url, config)
    if method == "radius":
        from secrets_env.providers.vault.auth.userpass import RADIUSAuth
        return RADIUSAuth.create(url, config)
    if method == "token":
        from secrets_env.providers.vault.auth.token import TokenAuth
        return TokenAuth.create(url, config)
    if method == "userpass":
        from secrets_env.providers.vault.auth.userpass import UserPassAuth
        return UserPassAuth.create(url, config)
    # fmt: on

    raise ValueError(f"Unknown auth method: {method}")

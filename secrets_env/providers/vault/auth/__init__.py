from __future__ import annotations

import logging
import typing
from secrets_env.exceptions import ConfigError

if typing.TYPE_CHECKING:
    from secrets_env.providers.vault.auth.base import Auth


logger = logging.getLogger(__name__)


def create_auth_by_name(url: str, config: dict) -> Auth:
    """
    Create an instance of the authentication class by the provided name.
    """
    logging.debug('Creating "%s" auth', config["method"])
    method: str = config["method"].lower()

    # fmt: off
    if method == "basic":
        from secrets_env.providers.vault.auth.userpass import BasicAuth
        return BasicAuth.create(url, config)
    elif method == "ldap":
        from secrets_env.providers.vault.auth.userpass import LDAPAuth
        return LDAPAuth.create(url, config)
    elif method == "null":
        from secrets_env.providers.vault.auth.base import NullAuth
        return NullAuth.create(url, config)
    elif method == "oidc":
        from secrets_env.providers.vault.auth.oidc import OpenIDConnectAuth
        return OpenIDConnectAuth.create(url, config)
    elif method == "okta":
        from secrets_env.providers.vault.auth.userpass import OktaAuth
        return OktaAuth.create(url, config)
    elif method == "radius":
        from secrets_env.providers.vault.auth.userpass import RADIUSAuth
        return RADIUSAuth.create(url, config)
    elif method == "token":
        from secrets_env.providers.vault.auth.token import TokenAuth
        return TokenAuth.create(url, config)
    # fmt: on

    raise ConfigError(f'Unknown auth method: "{method}"')

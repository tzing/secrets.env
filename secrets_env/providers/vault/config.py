import importlib
import logging
import typing
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

from secrets_env.io import get_env_var
from secrets_env.utils import ensure_dict, ensure_path, ensure_str

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.providers.vault.auth.base import Auth

DEFAULT_AUTH_METHOD = "token"

AUTH_METHODS = {
    "basic": ("secrets_env.providers.vault.auth.userpass", "BasicAuth"),
    "ldap": ("secrets_env.providers.vault.auth.userpass", "LDAPAuth"),
    "null": ("secrets_env.providers.vault.auth.null", "NoAuth"),
    "oidc": ("secrets_env.providers.vault.auth.oidc", "OpenIDConnectAuth"),
    "okta": ("secrets_env.providers.vault.auth.userpass", "OktaAuth"),
    "radius": ("secrets_env.providers.vault.auth.userpass", "RADIUSAuth"),
    "token": ("secrets_env.providers.vault.auth.token", "TokenAuth"),
}


logger = logging.getLogger(__name__)


def get_url(data: dict) -> Optional[str]:
    url = get_env_var("SECRETS_ENV_ADDR", "VAULT_ADDR")
    if not url:
        url = data.get("url", None)

    if not url:
        logger.error(
            "Missing required config <mark>url</mark>. "
            "Please provide from config file (<mark>source.url</mark>) "
            "or environment variable (<mark>SECRETS_ENV_ADDR</mark>)."
        )
        return None

    url, ok = ensure_str("source.url", url)
    if not ok:
        return None

    return url


def get_auth(data: dict) -> Optional["Auth"]:
    # syntax sugar: `auth: <method>`
    if isinstance(data, str):
        data = {"method": data}

    # type check
    data, _ = ensure_dict("source.auth", data)

    # extract auth method
    method = get_env_var("SECRETS_ENV_METHOD")
    if not method:
        method = data.get("method")

    if not method:
        method = DEFAULT_AUTH_METHOD
        logger.warning(
            "Missing required config <mark>auth method</mark>. "
            "Use default method <data>%s</data>",
            DEFAULT_AUTH_METHOD,
        )

    method, _ = ensure_str("auth method", method)
    if not method:
        return None

    # get auth class (import by name)
    module_name, class_name = AUTH_METHODS.get(method.lower(), (None, None))
    if not module_name or not class_name:
        logger.error("Unknown auth method: <data>%s</data>", method)
        return None

    module = importlib.import_module(module_name)
    class_: "Auth" = getattr(module, class_name)

    # build auth object from data
    return class_.load(data)

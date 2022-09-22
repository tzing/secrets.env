import logging
import os
import re
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import secrets_env.auth

from .file import build_config_file_metadata, find_config_file, read_config_file
from .parse import parse_path
from .types import Config
from .types import ConfigFileMetadata as ConfigFile
from .types import SecretPath as SecretResource

logger = logging.getLogger(__name__)


def find_config(*args, **kwargs):
    pass


def load_config(path: Optional[Path] = None) -> Optional[Config]:
    """Load the configurations and formated in to the typed structure. Values
    are loaded NOT ONLY from the config file, it could be:
      1. environment variable
      2. config file
      3. system keyring service
      4. prompt
    When a value has more than one occurrence, the first occurrence would be
    selected based on the order above.
    """
    # find config file
    if path:
        file_metadata = build_config_file_metadata(path)
    else:
        file_metadata = find_config_file()

    if not file_metadata:
        logger.debug("Config file not found.")
        return None

    logger.info("Read secrets.env config from <data>%s</data>", file_metadata.path)

    # read it
    data = read_config_file(file_metadata)
    if not data:
        logger.debug("Configure section not found. Stop loading secrets.")
        return None

    # parse
    config, ok = _loads(data)
    if not ok:
        return None

    return config


def _loads(data: dict) -> Tuple[Config, bool]:  # noqa: CCR001
    """Loads config from various sources and structure them into the Config
    object.

    This function tries to parse every thing instead of raise the error
    immediately. This behavior is preserved to expose every potential errors to
    users.
    """
    ok = True

    def assert_type(name: str, expect: str, obj: Any):
        nonlocal ok
        __defaults = {
            "str": (str, None),
            "dict": (dict, {}),
        }
        __max_len = 20

        # check type
        type_, default_value = __defaults[expect]
        if isinstance(obj, type_):
            return obj

        # print error message
        preview = str(obj)
        if len(preview) > __max_len:
            preview = preview[: __max_len - 3] + "..."

        logger.error(
            f"Config malformed: <data>{name}</data>. "
            f"Expected <mark>{expect}</mark> type, "
            f"got '<data>{preview}</data>' (<mark>{type(obj).__name__}</mark> type)."
        )

        ok = False
        return default_value

    # 'source' section - address and auth
    data_source = data.get("source", {})
    data_source = assert_type("source", "dict", data_source)

    # url
    url = os.getenv("SECRETS_ENV_ADDR")
    if not url:
        url = os.getenv("VAULT_ADDR")
    if not url:
        url = data_source.get("url", None)

    if url:
        url = assert_type("source.url", "str", url)
    else:
        logger.error(
            "Missing required config: <data>url</data>. Neither the value "
            "'<mark>source.url</mark>' in the config file nor the environment "
            "variable '<mark>SECRETS_ENV_ADDR</mark>' is found."
        )
        ok = False

    # auth method
    data_auth = data_source.get("auth", {})
    if isinstance(data_auth, str):
        # allow `auth: token` syntax in config
        data_auth = {
            "method": data_auth,
        }

    data_auth = assert_type("auth", "dict", data_auth)

    auth = secrets_env.auth.load_auth(data_auth)
    if not auth:
        ok = False

    # 'secrets' section
    data_secrets = data.get("secrets", {})
    if data_secrets:
        data_secrets = assert_type("secrets", "dict", data_secrets)
    else:
        logger.warning(
            "'<mark>secrets</mark>' section is empty. No data would be loaded."
        )
        data_secrets = {}

    secrets = {}
    for name, spec in data_secrets.items():
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name):
            logger.warning(
                "Target environment variable '<data>%s</data>' is not a "
                "valid name. Skipping this variable.",
                name,
            )
            continue

        resource = parse_path(name, spec)
        if resource:
            secrets[name] = resource

    return Config(url=url, auth=auth, secret_specs=secrets), ok

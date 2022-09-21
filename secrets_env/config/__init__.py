import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional, Tuple, Union

import secrets_env.auth

from .types import Config, ConfigFileMetadata as ConfigFile, SecretResource

logger = logging.getLogger(__name__)


def find_config(*args, **kwargs):
    pass


def use_config(filepath: Path) -> Optional[ConfigFile]:
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
        file_metadata = use_config(path)
    else:
        file_metadata = find_config()

    if not file_metadata:
        logger.debug("Config file not found.")
        return None

    logger.info("Read secrets.env config from <data>%s</data>", file_metadata.path)

    # read it
    if file_metadata.lang == "TOML":
        data = load_toml_file(file_metadata.path)
    elif file_metadata.lang == "YAML":
        data = load_yaml_file(file_metadata.path)
    elif file_metadata.lang == "JSON":
        data = load_json_file(file_metadata.path)
    else:
        raise RuntimeError(f"Unexpected format: {file_metadata.spec}")

    if data and not isinstance(data, dict):
        logger.warning("Configuration file is malformed. Stop loading secrets.")
        return None

    if file_metadata.spec == "pyproject.toml":
        data = data.get("tool", {}).get("secrets-env", {})

    if not data:
        logger.debug("Configure section not found. Stop loading secrets.")
        return None

    # parse
    config, ok = _loads(data)
    if not ok:
        return None

    return config


def load_toml_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = tomllib.load(fp)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load TOML file: %s", path)
            return None
    return data


def load_yaml_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = yaml.load(fp, Loader=yaml.SafeLoader)
        except (yaml.error.YAMLError, UnicodeDecodeError):
            logger.exception("Failed to load YAML file: %s", path)
            return None
    return data


def load_json_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = json.load(fp)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load JSON file: %s", path)
            return None
    return data


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

        resource = parse_resource(name, spec)
        if resource:
            secrets[name] = resource

    return Config(url=url, auth=auth, secret_specs=secrets), ok


def parse_resource(name: str, spec: Union[str, dict]) -> Optional[SecretResource]:
    """Convert the resource spec in the config file into the SecretResource
    object. Allows both string input and dict input.
    """
    if isinstance(spec, str):
        # string input: path#key
        idx = spec.find("#")
        if idx > 0:
            path = spec[:idx]
            key = spec[idx + 1 :]
            return SecretResource(path, key)

        logger.warning(
            "Target secret '<data>%s</data>' is invalid. Failed to resolve "
            "resource '<data>%s</data>'. Skipping this variable.",
            name,
            spec,
        )

    elif isinstance(spec, dict):
        # dict input
        path = spec.get("path")
        key = spec.get("key")
        if isinstance(path, str) and isinstance(key, str):
            return SecretResource(path, key)

        logger.warning(
            "Target secret '<data>%s</data>' is invalid. Missing resource spec "
            "'<mark>path</mark>' or '<mark>key</mark>'. Skipping this variable.",
            name,
        )

    else:
        logger.warning(
            "Target secret '<data>%s</data>' is invalid. Not a valid resource spec. "
            "Skipping this variable.",
            name,
        )

    return None

import importlib
import importlib.util
import json
import logging
import os
import re
import typing
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import secrets_env.auth


def _import_any(*module):
    """Import any of these modules if it exists."""
    for name in module:
        if importlib.util.find_spec(name):
            return importlib.import_module(name)
    return None


tomllib = _import_any("tomllib", "tomli")
yaml = _import_any("yaml")

if typing.TYPE_CHECKING:
    import tomli as tomllib
    import yaml

__has_lib_toml = tomllib is not None
__has_lib_yaml = yaml is not None


class ConfigFile(typing.NamedTuple):
    filename: str
    spec: str  # Literal["json", "yaml", "toml", "pyproject.toml"]
    enable: bool
    path: Optional[Path] = None

    @property
    def lang(self) -> str:
        if self.spec == "pyproject.toml":
            return "TOML"
        return self.spec.upper()


CONFIG_FILES = (
    ConfigFile(".secrets-env.toml", "toml", __has_lib_toml),
    ConfigFile(".secrets-env.yaml", "yaml", __has_lib_yaml),
    ConfigFile(".secrets-env.yml", "yaml", __has_lib_yaml),
    ConfigFile(".secrets-env.json", "json", True),
    ConfigFile("pyproject.toml", "pyproject.toml", __has_lib_toml),
)

logger = logging.getLogger(__name__)


def find_config(directory: Optional[Path] = None) -> Optional[ConfigFile]:
    """Find configuration file.

    It looks up for the file(s) that matches the name defined in ``CONFIG_FILE_SPECS``
    in current directory and parent directories.
    """
    wd = directory or Path.cwd().absolute()
    cnt_hit_root = 0  # counter for only search in root directory once
    while cnt_hit_root < 2:
        # look up for candidates
        for spec in CONFIG_FILES:
            candidate = wd / spec.filename
            if not candidate.is_file():
                continue

            if not spec.enable and warn_lang_support_issue(spec.lang):
                logger.warning("Skip config file <data>%s</data>.", candidate.name)
                continue

            return ConfigFile(*spec[:3], candidate)

        # go to parent directory
        parent = wd.parent
        if parent == wd:
            cnt_hit_root += 1

        wd = parent

    return None


def warn_lang_support_issue(format_: str) -> bool:
    """Check if the given file type is supportted or not."""
    warned_formats = vars(warn_lang_support_issue).setdefault("warned_formats", set())
    if format_ in warned_formats:
        return False

    warned_formats.add(format_)
    logger.warning("Optional dependency for <mark>%s</mark> is not installed.", format_)
    return True


class SecretResource(typing.NamedTuple):
    path: str
    key: str


class Config(typing.NamedTuple):
    url: str
    auth: secrets_env.auth.Auth
    secret_specs: Dict[str, SecretResource]


def load_config() -> Optional[Config]:
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


def _loads(data: dict) -> Tuple[Config, bool]:
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
    auth = load_auth(data_auth)
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

        resource = extract_resource_spec(name, spec)
        if resource:
            secrets[name] = resource

    return Config(url=url, auth=auth, secret_specs=secrets), ok


def load_auth(data: Union[dict, str]) -> Optional[secrets_env.auth.Auth]:
    """Load the authentication information. This function is a wrapper of
    `auth.load_auth` and handles syntax variation."""
    # allow `auth: token` syntax in config
    if isinstance(data, str):
        data = {
            "method": data,
        }

    # check type
    if not isinstance(data, dict):
        logger.error(
            "Config malformed: <data>auth</data>. Expected <mark>dict</mark> "
            "type, got <mark>%s</mark> type",
            type(data).__name__,
        )
        return None

    # get auth method
    return secrets_env.auth.load_auth(data)


def extract_resource_spec(
    name: str, spec: Union[str, dict]
) -> Optional[SecretResource]:
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

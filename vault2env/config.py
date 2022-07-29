import importlib
import importlib.util
import json
import logging
import os
import re
import typing
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import vault2env.auth


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


class ConfigFileSpec(typing.NamedTuple):
    filename: str
    format: str  # Literal["json", "yaml", "toml", "pyproject.toml"]
    enable: bool
    path: Optional[Path] = None


ORDERED_CONFIG_FILE_SPECS = (
    ConfigFileSpec(".vault2env.toml", "toml", __has_lib_toml),
    ConfigFileSpec(".vault2env.yaml", "yaml", __has_lib_yaml),
    ConfigFileSpec(".vault2env.yml", "yaml", __has_lib_yaml),
    ConfigFileSpec(".vault2env.json", "json", True),
    ConfigFileSpec("pyproject.toml", "pyproject.toml", __has_lib_toml),
)

logger = logging.getLogger(__name__)


def find_config() -> Optional[ConfigFileSpec]:
    """Find configuration file.

    It looks up for the file(s) that matches the name defined in ``CONFIG_FILE_SPECS``
    in current directory and parent directories.
    """
    wd = Path.cwd().absolute()
    cnt_hit_root = 0  # counter for only search in root directory once
    while cnt_hit_root < 2:
        # look up for candidates
        for spec in ORDERED_CONFIG_FILE_SPECS:
            if not spec.enable:
                continue
            candidate = wd / spec.filename
            if candidate.is_file():
                return ConfigFileSpec(*spec[:3], candidate)

        # go to parent directory
        parent = wd.parent
        if parent == wd:
            cnt_hit_root += 1

        wd = parent

    return None


class SecretResource(typing.NamedTuple):
    path: str
    key: str


class ConfigSpec(typing.NamedTuple):
    url: str
    auth: vault2env.auth.Auth
    secret_specs: Dict[str, SecretResource]


def load_config() -> Optional[ConfigSpec]:
    """Load the configurations and formated in to the typed structure. Values
    are loaded NOT ONLY from the config file, it could be:
      1. config file
      2. environment variable
      3. system keyring service
    When a value has more than one occurrence, the first occurrence would be
    selected based on the order above.
    """
    # find config file
    spec = find_config()
    if not spec:
        logger.debug("Config file not found.")
        return None

    logger.info("Read config from <data>%s</data>", spec.path)

    # read it
    if spec.format == "toml":
        data = load_toml_file(spec.path)
    elif spec.format == "pyproject.toml":
        data = load_toml_file(spec.path)
    elif spec.format == "yaml":
        data = load_yaml_file(spec.path)
    elif spec.format == "json":
        data = load_json_file(spec.path)
    else:
        raise RuntimeError(f"Unexpected format: {spec.format}")

    if not isinstance(data, dict):
        logger.warning("Configuration file is malformed. Data not loaded.")
        return None

    if spec.format == "pyproject.toml":
        data = data.get("tool", {}).get("vault2env", {})

    if not data:
        logger.warning("Required configure section not found. Data not loaded.")
        return None

    # parse
    spec, ok = extract(data)
    if not ok:
        logger.warning("Failed to parse config.")
        return None

    return spec


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


def extract(data: dict) -> Tuple[ConfigSpec, bool]:
    """Extract the config data, environment variable or system and structure
    them into the ConfigSpec object.

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
            "Config malformed: %s. Expected %s type, got '%s' (%s type)",
            name,
            expect,
            preview,
            type(obj).__name__,
        )

        ok = False
        return default_value

    # 'core' section - address and auth
    data_core = data.get("core", {})
    data_core = assert_type("core", "dict", data_core)

    # url
    url = data_core.get("url", None)
    if not url:
        url = os.getenv("VAULT_ADDR")

    if url:
        url = assert_type("core.url", "str", url)
    else:
        logger.error(
            "Missing required config: url. Neither the value 'core.url' in "
            "the config file nor the environment variable 'VAULT_ADDR' found."
        )
        ok = False

    # auth method
    data_auth = data_core.get("auth", {})
    auth = build_auth(data_auth)
    if not auth:
        ok = False

    # 'secrets' section
    data_secrets = data.get("secrets", {})
    if data_secrets:
        data_secrets = assert_type("secrets", "dict", data_secrets)
    else:
        logger.warning("'secrets' section is empty. No data would be loaded.")
        data_secrets = {}

    secrets = {}
    pattern_var_name = re.compile(r"[A-Z_][A-Z0-9_]*")
    for name, spec in data_secrets.items():
        if not pattern_var_name.fullmatch(name):
            logger.warning(
                "Secret invalid: %s. Not a valid variable name format. "
                "Skipping this variable.",
                name,
            )
            continue

        resource = extract_resource_spec(name, spec)
        if resource:
            secrets[name] = resource

    return ConfigSpec(url=url, auth=auth, secret_specs=secrets), ok


def build_auth(data: dict) -> Optional[vault2env.auth.Auth]:
    """Factory for building Auth object."""
    # get method from 'auth'
    if isinstance(data, str):
        # allowing `auth: token` style in config
        method = data
        data = {}
    elif not isinstance(data, dict):
        # type error
        logger.error(
            "Config malformed: auth. Expected dict type, got %s type",
            type(data).__name__,
        )
        return None
    else:
        # must be dict here
        method = data.get("method")

    # 'method' not exists in config file, use env var
    if not method:
        method = os.getenv("VAULT_METHOD")

    # 'method' still not found - return with error
    if not method:
        logger.error(
            "Missing required config: method. Neither the value 'core.auth.method'"
            " in the config file nor the environment variable 'VAULT_METHOD' found."
        )
        return None

    # build auth object based on auth
    if method == "token":
        return vault2env.auth.TokenAuth.load(data)
    elif method == "okta":
        return vault2env.auth.OktaAuth.load(data)

    logger.error("Unknown auth method: %s", method)
    return None


def extract_resource_spec(name: str, spec) -> Optional[SecretResource]:
    if isinstance(spec, str):
        resource = extract_path(spec)
        if resource:
            return resource
        else:
            logger.warning(
                "Secret invalid: %s. Failed to resolve the resource '%s'. "
                "Skipping this variable.",
                name,
                spec,
            )

    elif isinstance(spec, dict):
        path = spec.get("path")
        key = spec.get("key")
        if isinstance(path, str) and isinstance(key, str):
            return SecretResource(path, key)
        else:
            logger.warning(
                "Secret invalid: %s. Missing resource spec 'path' or 'key'. "
                "Skipping this variable.",
                name,
            )

    else:
        logger.warning(
            "Secret invalid: %s. Not a valid resource spec. Skipping this variable.",
            name,
        )

    return None


def extract_path(s: str) -> Optional[SecretResource]:
    """Extract secret path and key."""
    idx = s.find("#")
    if idx < 0:
        return None

    path = s[:idx]
    key = s[idx + 1 :]
    return SecretResource(path, key)

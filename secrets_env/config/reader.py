import json
import logging
import typing
from typing import Optional

from secrets_env.exceptions import UnsupportedError

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.config.finder import ConfigFile


logger = logging.getLogger(__name__)


def read_config_file(spec: "ConfigFile") -> dict:
    """Read the file."""
    if spec.lang == "toml":
        data = read_toml_file(spec.path)
    elif spec.lang == "yaml":
        data = read_yaml_file(spec.path)
    elif spec.lang == "json":
        data = read_json_file(spec.path)
    else:
        raise UnsupportedError(f"Unexpected format: {spec.format}")

    if data and not isinstance(data, dict):
        logger.warning("Config should be key value pairs. Got %s.", type(data).__name__)
        return {}

    data = data or {}

    if spec.format == "pyproject.toml":
        data = data.get("tool", {}).get("secrets-env", {})

    return data or {}


def read_toml_file(path: "Path") -> Optional[dict]:
    try:
        import tomllib  # pyright: ignore[reportMissingImports]
    except ImportError:
        import tomli as tomllib

    with open(path, "rb") as fp:
        try:
            data = tomllib.load(fp)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load TOML file: %s", path)
            return None
    return data


def read_yaml_file(path: "Path") -> Optional[dict]:
    try:
        import ruamel.yaml
        import ruamel.yaml.error

        loader = ruamel.yaml.YAML(typ="safe")
        parser = loader.load
        error = ruamel.yaml.error.YAMLError

    except ImportError:
        import yaml

        parser = yaml.safe_load
        error = yaml.error.YAMLError

    with open(path, "rb") as fp:
        try:
            data = parser(fp)
        except (error, UnicodeDecodeError):
            logger.exception("Failed to load YAML file: %s", path)
            return None
    return data


def read_json_file(path: "Path") -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = json.load(fp)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load JSON file: %s", path)
            return None
    return data

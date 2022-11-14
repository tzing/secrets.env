import json
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


def read_config_file(spec: "ConfigFile") -> Optional[dict]:
    """Read the file."""
    if spec.lang == "TOML":
        data = read_toml_file(spec.path)
    elif spec.lang == "YAML":
        data = read_yaml_file(spec.path)
    elif spec.lang == "JSON":
        data = read_json_file(spec.path)
    else:
        raise RuntimeError(f"Unexpected format: {spec.format}")

    if data and not isinstance(data, dict):
        logger.warning("Config should be key value pairs. Got %s.", type(data).__name__)
        return None

    data = data or {}

    if spec.format == "pyproject.toml":
        data = data.get("tool", {}).get("secrets-env", {})

    return data


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
    import yaml

    with open(path, "rb") as fp:
        try:
            data = yaml.safe_load(fp)
        except (yaml.error.YAMLError, UnicodeDecodeError):
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

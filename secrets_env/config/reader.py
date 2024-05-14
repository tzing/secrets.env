from __future__ import annotations

import logging
import typing
from pathlib import Path

if typing.TYPE_CHECKING:
    import os

from secrets_env.exceptions import ConfigError, UnsupportedError

logger = logging.getLogger(__name__)


def read(path: os.PathLike) -> dict:
    """Read the file."""
    filepath = Path(path)
    if not filepath.is_file():
        raise ConfigError(f"File not found: {filepath}")

    if filepath.suffix == ".toml":
        data = read_toml_file(filepath)
    elif filepath.suffix in (".yaml", ".yml"):
        data = read_yaml_file(filepath)
    elif filepath.suffix == ".json":
        data = read_json_file(filepath)
    else:
        raise UnsupportedError(f"Unexpected format: {filepath.suffix}")

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ConfigError("Expect key-value pairs in the config file")

    if filepath.name == "pyproject.toml":
        data = data.get("tool", {}).get("secrets-env", {})

    return data or {}


def read_toml_file(path: Path) -> dict | None:
    try:
        import tomllib  # pyright: ignore[reportMissingImports]
    except ImportError:
        import tomli as tomllib  # pyright: ignore[reportMissingImports]

    with path.open("rb") as fd:
        try:
            return tomllib.load(fd)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            logger.exception("Failed to parse TOML file: %s", path)
            return None


def read_yaml_file(path: Path) -> dict | None:
    import yaml

    with path.open("rb") as fd:
        try:
            return yaml.safe_load(fd)
        except yaml.YAMLError:
            logger.exception("Failed to parse YAML file: %s", path)
            return None


def read_json_file(path: Path) -> dict | None:
    import json

    with path.open("rb") as fd:
        try:
            return json.load(fd)
        except json.JSONDecodeError:
            logger.exception("Failed to parse JSON file: %s", path)
            return None

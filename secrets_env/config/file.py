import importlib
import importlib.util
import itertools
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Set

from secrets_env.config.types import ConfigFileMetadata


def import_any(*module):
    """Import any of these modules if it exists."""
    for name in module:
        if importlib.util.find_spec(name):
            return importlib.import_module(name)
    return None


tomllib = import_any("tomllib", "tomli")
yaml = import_any("yaml")

__has_lib_toml = tomllib is not None
__has_lib_yaml = yaml is not None

CONFIG_FILES = (
    ConfigFileMetadata(".secrets-env.toml", "toml", __has_lib_toml),
    ConfigFileMetadata(".secrets-env.yaml", "yaml", __has_lib_yaml),
    ConfigFileMetadata(".secrets-env.yml", "yaml", __has_lib_yaml),
    ConfigFileMetadata(".secrets-env.json", "json", True),
    ConfigFileMetadata("pyproject.toml", "pyproject.toml", __has_lib_toml),
)


logger = logging.getLogger(__name__)


def is_supportted(meta: ConfigFileMetadata) -> bool:
    """Helper function to check if this config file is supportted. Show the
    warning message when dependency is not installed."""
    if meta.enable:
        return True

    warned_formats: Set[str] = vars(is_supportted).setdefault("warned_formats", set())
    if meta.lang not in warned_formats:
        warned_formats.add(meta.lang)
        logger.warning(
            "This app currently cannot parse <mark>%s</mark> file: "
            "related dependency is not installed.",
            meta.lang,
        )

    return False


def find_config_file(directory: Optional[Path] = None) -> Optional[ConfigFileMetadata]:
    """Find configuration file.

    It looks up for the file(s) that matches the name defined in ``CONFIG_FILES``
    in current directory and parent directories.
    """
    if directory is None:
        directory = Path.cwd().absolute()

    # lookup config files in each parent directories
    for dir_ in itertools.chain([directory], directory.parents):
        # lookup config files of each formats
        for meta in CONFIG_FILES:
            candidate = dir_ / meta.filename
            if not candidate.is_file():
                continue

            if not is_supportted(meta):
                logger.warning("Skip config file <data>%s</data>.", candidate.name)
                continue

            return ConfigFileMetadata(*meta[:3], candidate)

    return None


def build_config_file_metadata(path: Path) -> Optional[ConfigFileMetadata]:
    """Converts this file into internal object for using it as the config."""
    # guess file type by file name
    assume_spec = None

    if path.name.lower() == "pyproject.toml":
        assume_spec = "pyproject.toml"
    elif (file_ext := path.suffix.lower()) in (".yml", ".yaml"):
        assume_spec = "yaml"
    elif file_ext == ".toml":
        assume_spec = "toml"
    elif file_ext == ".json":
        assume_spec = "json"

    if not assume_spec:
        logger.error("Failed to detect file format of <data>%s</data>.", path.name)
        return None

    # build into ConfigFileMetadata object
    meta = next(s for s in CONFIG_FILES if s.spec == assume_spec)

    if not is_supportted(meta):
        logger.warning("Failed to use config file <data>%s</data>.", path)
        return None

    return ConfigFileMetadata(
        filename=path.name,
        spec=meta.spec,
        enable=meta.enable,
        path=path,
    )


def read_config_file(meta: ConfigFileMetadata) -> Optional[Dict[str, Any]]:
    """Read the file."""
    if meta.lang == "TOML":
        data = read_toml_file(meta.path)
    elif meta.lang == "YAML":
        data = read_yaml_file(meta.path)
    elif meta.lang == "JSON":
        data = read_json_file(meta.path)
    else:
        raise RuntimeError(f"Unexpected format: {meta.spec}")

    if data and not isinstance(data, dict):
        logger.warning("Config file is malformed: <data>%s</data>", meta.path)
        return None

    data = data or {}

    if meta.spec == "pyproject.toml":
        data = data.get("tool", {}).get("secrets-env", {})

    return data


def read_toml_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = tomllib.load(fp)
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load TOML file: %s", path)
            return None
    return data


def read_yaml_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = yaml.safe_load(fp)
        except (yaml.error.YAMLError, UnicodeDecodeError):
            logger.exception("Failed to load YAML file: %s", path)
            return None
    return data


def read_json_file(path: Path) -> Optional[dict]:
    with open(path, "rb") as fp:
        try:
            data = json.load(fp)
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.exception("Failed to load JSON file: %s", path)
            return None
    return data

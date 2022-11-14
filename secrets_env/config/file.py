import importlib
import importlib.util
import itertools
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Set


@dataclass
class ConfigFileSpec:
    filename: str
    format: Literal["json", "yaml", "toml", "pyproject.toml"]

    __LANGUAGE = {
        "json": "json",
        "yaml": "yaml",
        "toml": "toml",
        "pyproject.toml": "toml",
    }

    @property
    def lang(self) -> str:
        return self.__LANGUAGE[self.format]


@dataclass
class ConfigFile(ConfigFileSpec):
    path: Path


def check_installed(*modules) -> bool:
    """Check if any of listed module installed."""
    for name in modules:
        if importlib.util.find_spec(name):
            return True
    return False


LANGUAGE_ENABLED = {
    "json": True,
    "yaml": check_installed("yaml"),
    "toml": check_installed("tomllib", "tomli"),
}

CONFIG_FILE_FORMATS = (
    ConfigFileSpec(".secrets-env.toml", "toml"),
    ConfigFileSpec(".secrets-env.yaml", "yaml"),
    ConfigFileSpec(".secrets-env.yml", "yaml"),
    ConfigFileSpec(".secrets-env.json", "json"),
    ConfigFileSpec("pyproject.toml", "pyproject.toml"),
)


logger = logging.getLogger(__name__)


def find_config_file(cwd: Optional[Path] = None) -> Optional[ConfigFile]:
    """Find config file.

    It looks for the file that matches the name pre-defined in ``CONFIG_FILE_FORMATS``
    in the given directory and its parent directories.
    """
    if cwd is None:
        cwd = Path.cwd().absolute()

    for dir_ in itertools.chain([cwd], cwd.parents):
        for spec in CONFIG_FILE_FORMATS:
            candidate = dir_ / spec.filename
            if not candidate.is_file():
                continue

            if not is_supportted(spec.lang):
                logger.warning("Skip config file <data>%s</data>.", candidate.name)
                continue

            return ConfigFile(
                filename=spec.filename, format=spec.format, path=candidate
            )

    return None


def get_config_file_metadata(path: Path) -> Optional[ConfigFile]:
    """Add required internal metadata to the file path."""
    # guess file format
    assume_format = None

    if path.name == "pyproject.toml":
        assume_format = "pyproject.toml"
    elif (file_ext := path.suffix.lower()) in (".yml", ".yaml"):
        assume_format = "yaml"
    elif file_ext == ".toml":
        assume_format = "toml"
    elif file_ext == ".json":
        assume_format = "json"

    if not assume_format:
        logger.error("Failed to detect file format for <data>%s</data>.", path.name)
        return None

    metadata = ConfigFile(
        filename=path.name,
        format=assume_format,
        path=path,
    )

    if not is_supportted(metadata.lang):
        logger.warning("Failed to parse <data>%s</data>.", path)
        return None

    return metadata


def is_supportted(lang: str) -> bool:
    """Check if this config file is supportted. Show the warning message when
    dependency is not installed."""
    if LANGUAGE_ENABLED[lang]:
        return True

    internal_vars = vars(is_supportted)
    warned_formats: Set[str] = internal_vars.setdefault("warned_formats", set())
    if lang not in warned_formats:
        warned_formats.add(lang)
        logger.warning(
            "This app currently cannot parse <mark>%s</mark> file: "
            "dependency not satisfied.",
            lang,
        )

    return False

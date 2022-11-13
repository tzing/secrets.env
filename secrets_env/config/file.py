import importlib
import importlib.util
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Set


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
        return self.__LANGUAGE.get(self.format)


@dataclass
class ConfigFileMetadata(ConfigFileSpec):
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


def is_supportted(spec: ConfigFileSpec) -> bool:
    """Check if this config file is supportted. Show the warning message when
    dependency is not installed."""
    if LANGUAGE_ENABLED[spec.lang]:
        return True

    internal_vars = vars(is_supportted)
    warned_formats: Set[str] = internal_vars.setdefault("warned_formats", set())
    if spec.lang not in warned_formats:
        warned_formats.add(spec.lang)
        logger.warning(
            "This app currently cannot parse <mark>%s</mark> file: "
            "dependency not satisfied.",
            spec.lang,
        )

    return False

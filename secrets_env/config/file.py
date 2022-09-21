import importlib
import importlib.util
import itertools
import logging
from pathlib import Path
from typing import Optional, Set

from .types import ConfigFile


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
    ConfigFile(".secrets-env.toml", "toml", __has_lib_toml),
    ConfigFile(".secrets-env.yaml", "yaml", __has_lib_yaml),
    ConfigFile(".secrets-env.yml", "yaml", __has_lib_yaml),
    ConfigFile(".secrets-env.json", "json", True),
    ConfigFile("pyproject.toml", "pyproject.toml", __has_lib_toml),
)


logger = logging.getLogger(__name__)


def is_supportted(spec: ConfigFile) -> bool:
    """Helper function to check if this config file is supportted. Show the
    warning message when dependency is not installed."""
    if spec.enable:
        return True

    warned_formats: Set[str] = vars(is_supportted).setdefault("warned_formats", set())
    if spec.lang not in warned_formats:
        warned_formats.add(spec.lang)
        logger.warning(
            "This app currently cannot parse <mark>%s</mark> file: "
            "related dependency is not installed.",
            spec.lang,
        )

    return False


def find_config_file(directory: Optional[Path] = None) -> Optional[ConfigFile]:
    """Find configuration file.

    It looks up for the file(s) that matches the name defined in ``CONFIG_FILES``
    in current directory and parent directories.
    """
    if directory is None:
        directory = Path.cwd().absolute()

    # lookup config files in each parent directories
    for dir_ in itertools.chain([directory], directory.parents):
        # lookup config files of each formats
        for spec in CONFIG_FILES:
            candidate = dir_ / spec.filename
            if not candidate.is_file():
                continue

            if not is_supportted(spec):
                logger.warning("Skip config file <data>%s</data>.", candidate.name)
                continue

            return ConfigFile(*spec[:3], candidate)

    return None


def build_config_file_spec(path: Path) -> Optional[ConfigFile]:
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

    # build into ConfigFile object
    spec = next(s for s in CONFIG_FILES if s.spec == assume_spec)

    if not is_supportted(spec):
        logger.warning("Failed to use config file <data>%s</data>.", path)
        return None

    return ConfigFile(
        filename=path.name,
        spec=spec.spec,
        enable=spec.enable,
        path=path,
    )

from __future__ import annotations

import importlib
import importlib.util
import itertools
import logging
import typing
from dataclasses import dataclass
from pathlib import Path

import platformdirs

if typing.TYPE_CHECKING:
    from typing import Iterable, Literal

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConfigFileSpec:
    """Avaliable config file formats."""

    filename: str
    format: Literal["toml", "yaml", "json", "pyproject.toml"]


@dataclass(frozen=True)
class ConfigFile(ConfigFileSpec):
    path: Path


def find_local_config_file(cwd: Path | None = None) -> ConfigFile | None:
    """Find config file in current directory."""
    if cwd is None:
        cwd = Path.cwd()

    CONFIG_FILE_FORMATS = (
        ConfigFileSpec(".secrets-env.toml", "toml"),
        ConfigFileSpec(".secrets-env.yaml", "yaml"),
        ConfigFileSpec(".secrets-env.yml", "yaml"),
        ConfigFileSpec(".secrets-env.json", "json"),
        ConfigFileSpec("pyproject.toml", "pyproject.toml"),
    )

    for dir_ in itertools.chain([cwd], cwd.parents):
        if f := find_readable_file(dir_, CONFIG_FILE_FORMATS):
            return f
    return None


def find_readable_file(
    dirpath: Path, specs: Iterable[ConfigFileSpec]
) -> ConfigFile | None:
    for spec in specs:
        filepath = dirpath / spec.filename
        if not filepath.is_file():
            continue
        logger.debug("Find config file %s", filepath)

        if not is_readable_format(spec.format):
            logger.warning(
                "The config file <data>%s</data> was found, but the required "
                "dependency for <mark>%s</mark> format is not installed.",
                filepath,
                spec.format,
            )
            return

        return ConfigFile(spec.filename, spec.format, filepath)


def is_readable_format(fmt: str) -> bool:
    if fmt == "json":
        return True
    elif fmt == "yaml":
        return is_installed("yaml")
    elif fmt in ("toml", "pyproject.toml"):
        return is_installed("tomllib") or is_installed("tomli")
    return False


def is_installed(module: str) -> bool:
    try:
        if importlib.util.find_spec(module):
            return True
    except ImportError:
        ...
    return False

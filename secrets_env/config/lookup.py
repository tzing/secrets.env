from __future__ import annotations

import importlib
import importlib.util
import itertools
import logging
import typing
from pathlib import Path

import click

if typing.TYPE_CHECKING:
    from typing import Iterable

logger = logging.getLogger(__name__)


def find_local_config_file(cwd: Path | None = None) -> Path | None:
    """Find config file in current directory."""
    if cwd is None:
        cwd = Path.cwd()

    CONFIG_NAME_CANDIDATES = (
        ".secrets-env.toml",
        ".secrets-env.yaml",
        ".secrets-env.yml",
        ".secrets-env.json",
        "pyproject.toml",
    )

    for dir_ in itertools.chain([cwd], cwd.parents):
        if f := find_readable_file(dir_, CONFIG_NAME_CANDIDATES):
            return f
    return None


def find_user_config_file() -> Path:
    """Find config file in user home directory."""
    return Path(click.utils.get_app_dir("secrets-env")) / "config.json"


def find_readable_file(dirpath: Path, candidates: Iterable[str]) -> Path | None:
    for name in candidates:
        filepath = dirpath / name
        if not filepath.is_file():
            continue
        logger.debug("Find config file %s", filepath)

        if not is_readable_format(filepath.suffix):
            logger.warning(
                "The config file <data>%s</data> was found, but the required "
                "dependency for <mark>%s</mark> format is not installed.",
                filepath,
                filepath.suffix,
            )
            return

        return filepath


def is_readable_format(suffix: str) -> bool:
    if suffix == ".toml":
        return is_installed("tomllib") or is_installed("tomli")
    elif suffix in (".yaml", ".yml"):
        return is_installed("yaml")
    elif suffix == ".json":
        return True
    return False


def is_installed(module: str) -> bool:
    try:
        if importlib.util.find_spec(module):
            return True
    except ImportError:
        ...
    return False

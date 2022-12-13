"""
Hooks that powered by `pluggy <https://pluggy.readthedocs.io/en/stable/>`_.
All available hooks are listed in :py:class:`~secrets_env.hooks.HookSpec`.
"""
import typing
from typing import Any, Dict, Optional

import pluggy

if typing.TYPE_CHECKING:
    from secrets_env.reader import ReaderBase

APP_NAME = "secrets_env"

hookspec = pluggy.HookspecMarker(APP_NAME)
hookimpl = pluggy.HookimplMarker(APP_NAME)


class HookSpec:
    """All available hooks are listed in this class."""

    @hookspec
    def add_extra_config(self, data: Dict[str, Any]) -> None:
        """Add extra config values into config data dictionary. Triggerred before
        parsing them into the structured object.

        Parameters
        ----------
        data : dict
            Loaded config data dict. The hook is allowed to modify its content.
        """

    @hookspec
    def get_reader(self, type: str, data: Dict[str, Any]) -> Optional["ReaderBase"]:
        """Parse the config data and return reader.

        Parameters
        ----------
        type : str
            Reader type to be built. This value is same as the one extracted
            from ``data``.
        data : dict
            Part of config data dict.

        Returns
        -------
        reader : ReaderBase | None
            If ``type`` matches this provider, returns an reader instance. Or
            returns :py:obj:`None` otherwise.

            It is suggested to make the time-consuming steps (e.g. connection
            establishment) lazy evaluated.

        Raises
        ------
        ~secrets_env.exceptions.ConfigError
            The path dict is malformed.
        """


def get_hooks() -> HookSpec:
    manager = pluggy.PluginManager(APP_NAME)
    manager.load_setuptools_entrypoints(APP_NAME)
    manager.add_hookspecs(HookSpec)

    return typing.cast(HookSpec, manager.hook)

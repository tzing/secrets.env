"""
Hooks that powered by `pluggy <https://pluggy.readthedocs.io/en/stable/>`_.
All available hooks are listed in :py:class:`~secrets_env.hooks.HookSpec`.
"""
import typing
from typing import Any, Dict, Optional

import pluggy

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

APP_NAME = "secrets_env"

hookspec = pluggy.HookspecMarker(APP_NAME)
hookimpl = pluggy.HookimplMarker(APP_NAME)

_manager = None


class HookSpec:
    """All available hooks are listed in this class."""

    @hookspec()
    def add_extra_config(self, data: Dict[str, Any]) -> None:
        """Add extra config values into config data dictionary. Triggerred before
        parsing them into the structured object.

        Parameters
        ----------
        data : dict
            Loaded config data dict. The hook is allowed to modify its content.
        """

    @hookspec(firstresult=True)
    def get_provider(self, type: str, data: Dict[str, Any]) -> Optional["ProviderBase"]:
        """Parse the config data and return provider. This hook is only called
        when ``type`` not matches any of builtin providers.

        Parameters
        ----------
        type : str
            Unique provider name in lower case. This value should be the same as
            ``type`` field extracted from ``data``.
        data : dict
            Part of config data dict.

        Returns
        -------
        reader : ProviderBase | None
            If ``type`` matches this provider, returns an provider instance. Or
            returns :py:obj:`None` otherwise.

            It is suggested not to proceed the time-consuming steps (e.g.
            connection establishment) in this hook. Postponed those actions to
            :py:meth:`~secrets_env.provider.ProviderBase.get`.

        Raises
        ------
        ~secrets_env.exceptions.ConfigError
            The path dict is malformed.
        """


def get_hooks() -> HookSpec:
    global _manager
    if not _manager:
        _manager = pluggy.PluginManager(APP_NAME)
        _manager.load_setuptools_entrypoints(APP_NAME)
        _manager.add_hookspecs(HookSpec)
    return typing.cast(HookSpec, _manager.hook)

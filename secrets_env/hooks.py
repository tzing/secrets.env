import typing
from typing import Any, Dict

import pluggy

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


def get_hooks() -> HookSpec:
    manager = pluggy.PluginManager(APP_NAME)
    manager.load_setuptools_entrypoints(APP_NAME)
    manager.add_hookspecs(HookSpec)

    return typing.cast(HookSpec, manager.hook)

import typing

import pluggy

APP_NAME = "secrets_env"

hookspec = pluggy.HookspecMarker(APP_NAME)
hookimpl = pluggy.HookimplMarker(APP_NAME)


class HookSpec:
    @hookspec
    def add_extra_config(self, data: dict) -> None:
        """Add extra configs into config data dict. Triggerred before parsing
        them into the structured object.

        The input is the loaded dict object, and plugin developers could
        directly modifed its content.
        """


def get_hooks() -> HookSpec:
    manager = pluggy.PluginManager(APP_NAME)
    manager.load_setuptools_entrypoints(APP_NAME)
    manager.add_hookspecs(HookSpec)

    return typing.cast(HookSpec, manager.hook)

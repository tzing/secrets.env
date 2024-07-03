from __future__ import annotations

import os
import typing

if typing.TYPE_CHECKING:
    from secrets_env.console.shells.base import Shell


def get_shell() -> Shell:
    # fmt: off
    import secrets_env.realms.shellingham
    shell, path = secrets_env.realms.shellingham.detect_shell()

    if os.name == "nt":
        from secrets_env.shells.windows import WindowsShell
        return WindowsShell(path)

    from secrets_env.console.shells.posix import PosixShell
    return PosixShell(path)

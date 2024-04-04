from __future__ import annotations

import typing

from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import Request


class DebugProvider(Provider):
    """Internal provider for debugging purposes."""

    type = "debug"

    value: str

    def _get_value_(self, spec: Request) -> str:
        return self.value

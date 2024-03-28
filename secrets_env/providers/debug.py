from __future__ import annotations

import typing

from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec


class DebugProvider(Provider):
    """Internal provider for debugging purposes."""

    type = "debug"

    value: str

    def get(self, spec: RequestSpec) -> str:
        return self.value

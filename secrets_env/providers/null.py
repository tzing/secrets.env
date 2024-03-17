from __future__ import annotations

import typing

from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec


class NullProvider(Provider):
    """A provider that always returns empty string. This provider is preserved
    for debugging."""

    type = "null"

    def get(self, spec: RequestSpec) -> str:
        return ""

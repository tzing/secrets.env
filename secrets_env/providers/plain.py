from __future__ import annotations

import typing

from secrets_env.provider import AsyncProvider

if typing.TYPE_CHECKING:
    from secrets_env.provider import Request


class PlainTextProvider(AsyncProvider):
    """Plain text provider returns text that is copied directly from the
    configuration file."""

    type = "plain"

    async def _get_value_(self, spec: Request) -> str:
        if spec.value is None:
            raise LookupError("Value not provided in the configuration")
        return spec.value

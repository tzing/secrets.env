from __future__ import annotations

import typing

from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import Request


class PlainTextProvider(Provider):
    """Plain text provider returns text that is copied directly from the
    configuration file."""

    type = "plain"

    def _get_value_(self, spec: Request) -> str:
        if spec.value is None:
            raise LookupError("Value not provided in the configuration")
        return spec.value

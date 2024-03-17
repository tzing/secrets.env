from __future__ import annotations

import typing

from secrets_env.provider import Provider

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec


class PlainTextProvider(Provider):
    """Plain text provider returns text that is copied directly from the
    configuration file."""

    type = "plain"

    def get(self, spec: RequestSpec) -> str:
        if isinstance(spec, str):
            return spec
        elif isinstance(spec, dict):
            return spec.get("value") or ""

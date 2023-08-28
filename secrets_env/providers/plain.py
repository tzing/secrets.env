import typing

from secrets_env.exceptions import TypeError
from secrets_env.provider import ProviderBase

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec


class PlainTextProvider(ProviderBase):
    """Plain text provider returns text that is copied directly from the
    configuration file."""

    @property
    def type(self) -> str:
        return "plain"

    def get(self, spec: "RequestSpec") -> str:
        if isinstance(spec, str):
            value = spec
        elif isinstance(spec, dict):
            value = spec.get("value")
        else:
            raise TypeError("secret path spec", dict, spec)
        return value or ""


def get_provider(type_: str, data: dict) -> PlainTextProvider:
    return PlainTextProvider()

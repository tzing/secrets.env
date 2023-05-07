import typing

from secrets_env.provider import ProviderBase

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec


class NullProvider(ProviderBase):
    """A provider that always empty string. This type is preserved for debugging."""

    @property
    def type(self) -> str:
        return "null"

    def get(self, spec: "RequestSpec") -> str:
        return ""


def get_provider(type_: str, data: dict) -> NullProvider:
    return NullProvider()

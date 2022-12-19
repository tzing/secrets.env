import dataclasses
import typing

from .base import Auth


@dataclasses.dataclass
class NoAuth(Auth):
    """No authentication.

    Vault always require authentication. secrets.env core checks for a valid
    token before loading secrets. This class could only be used for testing and
    debugging.
    """

    @classmethod
    def method(cls) -> str:
        return "no-authentication"

    def login(self, client: typing.Any) -> None:
        return None

    @classmethod
    def load(cls, data: typing.Dict[str, typing.Any]) -> Auth:
        return cls()

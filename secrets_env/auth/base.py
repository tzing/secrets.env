import abc
import dataclasses
import typing
from typing import Any, Dict, Optional

if typing.TYPE_CHECKING:
    import httpx


class Auth(abc.ABC):
    """Base class for authentication schemes."""

    @abc.abstractclassmethod
    def method(cls) -> str:
        """Returns authentication method name."""
        raise NotImplementedError()

    @abc.abstractmethod
    def login(self, client: "httpx.Client") -> Optional[str]:
        """Login and get token."""

    @abc.abstractclassmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        """Initialize an instance of this class using the provided config data
        or internally load the secrets from the system."""


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

    def login(self, client: "httpx.Client") -> None:
        return None

    @classmethod
    def load(cls, data: Dict[str, Any]) -> Optional[Auth]:
        return cls()

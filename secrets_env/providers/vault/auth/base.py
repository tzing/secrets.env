import abc
import typing
from typing import Any, Dict, Optional

if typing.TYPE_CHECKING:
    import httpx


class Auth(abc.ABC):
    """Base class for authentication schemes."""

    @classmethod
    @abc.abstractmethod
    def method(cls) -> str:
        """Returns authentication method name."""
        raise NotImplementedError()

    @abc.abstractmethod
    def login(self, client: "httpx.Client") -> Optional[str]:
        """Login and get token."""

    @classmethod
    @abc.abstractmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        """Initialize an instance of this class using the provided config data
        or internally load the secrets from the system."""

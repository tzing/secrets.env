import abc
import typing
from typing import Any, Dict, Optional

if typing.TYPE_CHECKING:
    import httpx


class Auth(abc.ABC):
    """Base class for authentication schemes."""

    @abc.abstractclassmethod
    def method(cls) -> str:
        """Returns authentication name."""

    @abc.abstractmethod
    def login(self, client: "httpx.Client") -> str:
        """Login and get token."""

    @abc.abstractclassmethod
    def load(cls, data: Dict[str, Any]) -> Optional["Auth"]:
        """Initialize an instance of this class using the provided config data
        or internally load the secrets from the system."""

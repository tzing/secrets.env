from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

import pydantic

if TYPE_CHECKING:
    from typing import Any, Self

    import httpx
    from pydantic_core import Url


class Auth(pydantic.BaseModel, ABC):
    """Base class for authentication schemes."""

    model_config = {
        "frozen": True,
    }

    method: ClassVar[str]
    """Authentication method name."""

    @classmethod
    @abstractmethod
    def create(cls, url: Url, config: dict[str, Any]) -> Self:
        """
        Initialize an instance of this class using the provided config data
        or internally load the secrets from the system.
        """

    @abstractmethod
    def login(self, client: httpx.Client) -> str:
        """
        Login and get Vault token.

        Raises
        ------
        AuthenticationError
            If the login fails.
        """


class NoAuth(Auth):
    """No authentication.

    This class is used when no authentication is required.
    """

    method: ClassVar[str] = "null"

    token: str = ""

    @classmethod
    def create(cls, url: Any, config: dict[str, Any]) -> NoAuth:
        return cls()

    def login(self, client: Any) -> str:
        return self.token

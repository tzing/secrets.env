from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from typing import Any, Self

    from httpx import AsyncClient
    from pydantic import AnyUrl


class Auth(ABC, BaseModel):
    """Base class for authentication schemes."""

    model_config = ConfigDict(frozen=True)

    method: ClassVar[str]
    """Authentication method name."""

    @classmethod
    @abstractmethod
    def create(cls, url: AnyUrl, config: dict[str, Any]) -> Self:
        """
        Initialize an instance of this class using the provided config data
        or internally load the secrets from the system.
        """

    @abstractmethod
    async def login(self, client: AsyncClient) -> str:
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

    async def login(self, client: Any) -> str:
        return self.token

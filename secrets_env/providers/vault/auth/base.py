from __future__ import annotations

import typing
from abc import ABC, abstractmethod

import pydantic

if typing.TYPE_CHECKING:
    from typing import Any, Self

    import httpx


class Auth(pydantic.BaseModel, ABC):
    """Base class for authentication schemes."""

    model_config = {
        "frozen": True,
    }

    method: str
    """Authentication method name."""

    @classmethod
    @abstractmethod
    def create(cls, url: str, config: dict[str, Any]) -> Self | None:
        """
        Initialize an instance of this class using the provided config data
        or internally load the secrets from the system.
        """

    @abstractmethod
    def login(self, client: httpx.Client) -> str | None:
        """Login and get token."""


class NullAuth(Auth):
    """No authentication.

    This class is used when no authentication is required.
    """

    method: str = "null"

    @classmethod
    def create(cls, url: str, config: dict[str, Any]) -> NullAuth:
        return cls()

    def login(self, client: Any) -> None:
        return None

"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar, Union

from pydantic import BaseModel, field_validator, validate_call

RequestSpec = Union[dict[str, str], str]
""":py:class:`RequestSpec` represents a path spec to read the value.

It should be a :py:class:`dict` in most cases; or :py:class:`str` if this
provider accepts shortcut.
"""


class Request(BaseModel):
    name: str
    source: str | None = None

    # all possible fields
    field: str | list[str] | None = None
    format: str | None = None
    path: str | None = None
    value: str | None = None

    @field_validator("name", mode="after")
    @classmethod
    def _check_name_format(cls, value: str):
        if not re.fullmatch(r"[a-zA-Z_]\w*", value):
            raise ValueError("Invalid environment variable name")
        return value


class Provider(BaseModel, ABC):
    """Abstract base class for secret provider. All provider must implement
    this interface.
    """

    type: ClassVar[str]

    name: str | None = None

    @validate_call
    def __call__(self, spec: Request | RequestSpec) -> str:
        """Get value.

        Parameters
        ----------
        spec : Request
            Request specification for getting secret value.

        Return
        ------
        Returns the value on success.

        Raises
        ------
        ValidationError
            If the input format is invalid.
        UnsupportedError
            When this operation is not supported.
        AuthenticationError
            Failed during authentication.
        LookupError
            If the secret is not found.
        """
        if isinstance(spec, str):
            spec = Request(name="TEMP", value=spec)
        elif isinstance(spec, dict):
            spec = Request.model_validate(spec)
        return self._get_value_(spec)

    @abstractmethod
    def _get_value_(self, spec: Request) -> str:
        """Get value.

        Parameters
        ----------
        spec : Request
            Request specification for getting secret value.

        Return
        ------
        Returns the value on success.

        Raises
        ------
        ValidationError
            If the input format is invalid.
        UnsupportedError
            When this operation is not supported.
        AuthenticationError
            Failed during authentication.
        LookupError
            If the secret is not found.
        """

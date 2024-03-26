"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""

from __future__ import annotations

import abc
from typing import ClassVar, Union

from pydantic import BaseModel

RequestSpec = Union[dict[str, str], str]
""":py:class:`RequestSpec` represents a path spec to read the value.

It should be a :py:class:`dict` in most cases; or :py:class:`str` if this
provider accepts shortcut.
"""


class Provider(BaseModel, abc.ABC):
    """Abstract base class for secret provider. All provider must implement
    this interface.
    """

    type: ClassVar[str]

    name: str | None = None

    @abc.abstractmethod
    def get(self, spec: RequestSpec) -> str:
        """Get secret.

        Parameters
        ----------
        path : dict | str
            Raw input from config file for reading the secret value.

        Return
        ------
        The value

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

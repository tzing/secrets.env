"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from pydantic import BaseModel

RequestSpec = dict[str, str] | str
""":py:class:`RequestSpec` represents a path spec to read the value.

It should be a :py:class:`dict` in most cases; or :py:class:`str` if this
provider accepts shortcut.
"""


class Provider(BaseModel, abc.ABC):
    """Abstract base class for secret provider. All provider must implement
    this interface.
    """

    type: ClassVar[str]

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
        LookupError
            If the secret is not found.
        """

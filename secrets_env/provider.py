"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""
import abc
import sys
import typing
from typing import Dict, Union

if typing.TYPE_CHECKING:
    from secrets_env.exceptions import ConfigError, ValueNotFound  # noqa: F401

    if sys.version_info >= (3, 10):
        from typing import TypeAlias


RequestSpec: "TypeAlias" = Union[Dict[str, str], str]
""":py:class:`RequestSpec` represents a secret spec (name/path) to be loaded.
"""


class ProviderBase(abc.ABC):
    """Abstract base class for secret provider. All secret provider must implement
    this interface.
    """

    @property
    @abc.abstractmethod
    def type(self) -> str:
        """Provider name."""

    @abc.abstractmethod
    def get(self, spec: RequestSpec) -> str:
        """Get secret value.

        Parameters
        ----------
        spec : dict | str
            Raw input from config file.

            It should be :py:class:`dict` in most cases; or :py:class:`str` if
            this provider accepts shortcut.

        Return
        ------
        The secret value.

        Raises
        ------
        ConfigError
            The path dict is malformed.
        ValueNotFound
            The path dict is correct but the secret not exists.

        Note
        ----
        Key ``source`` is preserved in ``spec`` dictionary.
        """

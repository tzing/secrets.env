"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, Field, ValidationError, field_validator, validate_call

from secrets_env.exceptions import AuthenticationError, NoValue, UnsupportedError

logger = logging.getLogger(__name__)


class Request(BaseModel):
    """
    Specification for requesting a secret value.

    This class is used for parsing the ``secrets`` section from the configuration
    file. The field :attr:`name` and :attr:`source` are used by secrets.env core
    module, while the remaining fields are passed to the secret providers.

    Secrets.env uses :py:mod:`pydantic` to parse configurations and provide a
    valid :class:`Request` object to the secret providers. Therefore, all
    potential fields must be defined in this class.
    """

    name: str = Field(pattern=r"^[a-zA-Z_]\w*$")
    """
    The environment variable to store the secret value.
    """

    source: str | None = None
    """
    The provider name to request the value from. If this field is not specified,
    the default provider might be applied.
    """

    field: str | list[str] | None = None
    format: str | None = None
    key: str | None = None
    kind: str | None = None
    path: str | None = None
    ref: str | None = None
    value: str | None = None


class Provider(BaseModel, ABC):
    """
    Abstract base class for secret provider.

    The provider classes are initialized by the core module with the configuration
    file's ``sources`` section. The provider class must inherit this class and
    implement the abstract method :meth:`_get_value_` to get the secret value.

    The provider class is responsible for handling the authentication, lookup,
    and other operations to get the secret value. It is suggested to perform
    the connection and authentication lazy.
    """

    type: ClassVar[str]
    """
    Provider type name.
    """

    name: str = Field(default=None, validate_default=True)
    """
    Provider instance name.

    This field could be configured by the user in the configuration file.
    Otherwise, it will be set to the provider type name.
    """

    @field_validator("name", mode="before")
    @classmethod
    def _set_default_name_(cls, value: str | None) -> str:
        if value is None:
            return cls.type
        return value

    @validate_call
    def __call__(self, spec: Request) -> str:
        """
        The method invoked by the core module to get the secret value.

        This method is a wrapper around the :meth:`_get_value_` method. It
        catches the exceptions raised by the provider and logs the error
        messages, then raises the :class:`NoValue` exception.

        Parameters
        ----------
        spec : Request
            Request specification for getting secret value.

        Return
        ------
        Returns the value on success.

        Raises
        ------
        NoValue
            When failed to get value.
        """
        try:
            return self._get_value_(spec)
        except AuthenticationError as e:
            logger.warning(f"Authentication failed for <data>{spec.name}</data>: {e}")
            raise NoValue from e
        except LookupError as e:
            logger.warning(f"Value for <data>{spec.name}</data> not found: {e}")
            raise NoValue from e
        except UnsupportedError as e:
            logger.warning(f"Operation not supported for <data>{spec.name}</data>: {e}")
            raise NoValue from e
        except ValidationError as e:
            logger.warning(f"Request <data>{spec.name}</data> is malformed:")
            for err in e.errors():
                loc = ".".join(map(str, err["loc"])) or "(root)"
                msg = err["msg"]
                logger.warning(f"  \u279C <mark>{loc}</mark>: {msg}")
            logger.warning("Skipping <data>%s</data>", spec.name)
            raise NoValue from e
        except Exception as e:
            logger.error(f"Error requesting value for <data>{spec.name}</data>")
            logger.debug(f"Request= {spec!r}")
            logger.debug(f"Error= {type(e).__name__}, Msg= {e}", exc_info=True)
            raise NoValue from e

    @abstractmethod
    def _get_value_(self, spec: Request) -> str:
        """
        The method to get the secret value.

        This method must be implemented by the provider class. When any error
        occurs during the operation, the method should raise the appropriate
        exception. Read the `Raises` section for more details.

        Parameters
        ----------
        spec : Request
            Request specification for getting secret value.

        Return
        ------
        Returns the value on success.

        Raises
        ------
        AuthenticationError
            Failed during authentication.
        LookupError
            If the secret is not found.
        UnsupportedError
            When this operation is not supported.
        pydantic_core.ValidationError
            If the input format is invalid.
        """

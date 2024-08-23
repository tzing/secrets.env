"""This module contains types and abstract classes for building provider.

For secret provider implementations, see :py:mod:`secrets_env.providers`.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ValidationError, field_validator, validate_call

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

    name: str
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
    def __call__(self, spec: Request) -> str:
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
        AuthenticationError
            Failed during authentication.
        LookupError
            If the secret is not found.
        UnsupportedError
            When this operation is not supported.
        ValidationError
            If the input format is invalid.
        """

"""All exception types that might be raised from secrets.env core.
"""
import builtins
from typing import Any, Type, Union


class SecretsEnvError(Exception):
    """Base error type for secrets.env.

    :meta private:
    """

    def __init__(self, fmt: str, *args: Any, **extras: Any) -> None:
        """
        Constructor that applies :py:meth:`str.format` to message template.

        Parameters
        ----------
        fmt : str
            Error message template.
        args : Any
            Unnamed values to substitute the ``{}`` in the message template
        extras : Any
            Extra attributes to be attached to this exception instance.

        Example
        -------

        .. code-block:: python

           exc = SecretsEnvError("Demo exception for {}", "testing", key="kwarg example")

           print(exc)
           # Demo exception for testing

           print(f"{exc.key=}")
           # exc.key='kwarg example'
        """  # noqa: E501
        msg = fmt.format(*args)
        super().__init__(msg)
        for name, value in extras.items():
            setattr(self, name, value)


class AuthenticationError(SecretsEnvError):
    """Authentication failed."""


class ConfigError(SecretsEnvError, builtins.ValueError):
    """Configuration is malformed."""


class TypeError(SecretsEnvError, builtins.TypeError):
    """Inappropriate argument type.

    :meta private:
    """

    def __init__(self, name: str, expect: Union[str, Type], got: Any) -> None:
        self.name = name
        self.expect = expect.__name__ if isinstance(expect, type) else str(expect)
        self.got = type(got).__name__
        super().__init__(f"Expect {self.expect} for {self.name}, got {self.got}")


class UnsupportedError(SecretsEnvError):
    """The operation is unsupported."""


class ValueNotFound(SecretsEnvError, builtins.LookupError):
    """Requested value does not exist, or the user does not have permission to
    read it."""

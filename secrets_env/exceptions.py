"""All exception types that might be raised from secrets.env core.
"""
import builtins
from typing import Any, Type, Union


class SecretsEnvError(Exception):
    """Base error type for secrets.env.

    :meta private:
    """

    def __init__(self, fmt: str, *args: object, **kwargs: object) -> None:
        """
        Constructor that applies :py:meth:`str.format` to message template.

        Parameters
        ----------
        fmt : str
            Error message template.
        args : Any
            Unnamed values to substitute the ``{}`` in the message template
        kwargs : Any
            Named values to substitute the ``{name}`` in the message template
        """
        msg = fmt.format(*args, **kwargs)
        super().__init__(msg)


class AuthenticationError(SecretsEnvError):
    """Authentication failed."""


class ConfigError(SecretsEnvError, ValueError):
    """Configuration is malformed."""


class SecretNotFound(SecretsEnvError, LookupError):
    """A :py:exc:`LookupError` that indicates the requested secret does not exist
    or you do not have enough permission to touch it."""


class TypeError(SecretsEnvError, builtins.TypeError):
    """Inappropriate argument type."""

    def __init__(self, name: str, expect: Union[str, Type], got: Any) -> None:
        self.name = name
        self.expect = expect.__name__ if isinstance(expect, type) else str(expect)
        self.got = type(got).__name__
        super().__init__(f"Expect {self.expect} for {self.name}, got {self.got}")


class UnsupportedError(SecretsEnvError):
    """The operation is unsupported."""

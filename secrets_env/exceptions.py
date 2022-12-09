"""All exception types that might be raised from secrets.env core.
"""


class SecretsEnvError(Exception):
    """Base error type for secrets.env."""

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


class TypeError(SecretsEnvError, TypeError):
    """Inappropriate argument type."""


class UnsupportedError(SecretsEnvError):
    """The operation is unsupported."""

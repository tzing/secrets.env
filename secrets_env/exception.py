class VaultEnvError(Exception):
    """Base error type for errors in this module"""

    def __init__(self, msg: str, *args: object, **kwargs: object) -> None:
        """
        Constructor that applies `format()` to the message.

        Parameters
        ----------
        msg : str
            Error message template
        args : Any
            Unnamed values to substitute the `{}` in the message template
        kwargs : Any
            Named values to substitute the `{name}` in the message template
        """
        msg = msg.format(*args, **kwargs)
        super().__init__(msg)


class TypeError(VaultEnvError, TypeError):
    """Inappropriate argument type."""


class UnsupportedError(VaultEnvError):
    """The operation is unsupported."""


class AuthenticationError(VaultEnvError):
    """Authentication failed."""

"""All exception types that might be raised from secrets.env core.
"""

from __future__ import annotations

import builtins


class SecretsEnvError(Exception):
    """Base error type for secrets.env.

    :meta private:
    """


class AuthenticationError(SecretsEnvError):
    """Authentication failed."""


class ConfigError(SecretsEnvError, builtins.ValueError):
    """Configuration is malformed."""


class NoValue(SecretsEnvError):
    """No value was returned from the provider."""

    def __init__(self) -> None:
        super().__init__("No value was returned from the provider")


class UnsupportedError(SecretsEnvError):
    """The operation is unsupported."""


class OperationError(SecretsEnvError):
    """The operation failed."""

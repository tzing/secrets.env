"""All exception types that might be raised from secrets.env core.
"""

from __future__ import annotations

import builtins
import typing

if typing.TYPE_CHECKING:
    from typing import Any


class SecretsEnvError(Exception):
    """Base error type for secrets.env.

    :meta private:
    """


class AuthenticationError(SecretsEnvError):
    """Authentication failed."""


class ConfigError(SecretsEnvError, builtins.ValueError):
    """Configuration is malformed."""


class UnsupportedError(SecretsEnvError):
    """The operation is unsupported."""


class ValueNotFound(SecretsEnvError, builtins.LookupError):
    """Requested value does not exist, or the user does not have permission to
    read it."""

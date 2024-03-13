from __future__ import annotations

import logging
import typing
from functools import cached_property
from typing import Literal

from secrets_env.exceptions import ConfigError, ValueNotFound
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.helper import get_connection_param

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec
    from secrets_env.providers.teleport.config import TeleportUserConfig
    from secrets_env.providers.teleport.helper import TeleportConnectionParameter

DEFAULT_OUTPUT_FORMAT = "path"


class OutputSpec(typing.NamedTuple):
    field: Literal["uri", "ca", "cert", "key", "cert+key"]
    format: Literal["path", "pem"]


logger = logging.getLogger(__name__)


class TeleportProvider(ProviderBase):
    """Read certificates from Teleport."""

    @property
    def type(self) -> str:
        return "teleport"

    def __init__(self, *, config: TeleportUserConfig) -> None:
        self._config = config

    @cached_property
    def tsh(self) -> TeleportConnectionParameter:
        """Return teleport app connection information."""
        return get_connection_param(self._config)

    def get(self, spec: RequestSpec) -> str:
        parsed = parse_spec(spec)

        if parsed.field == "uri":
            return self.tsh.uri

        elif parsed.field == "ca":
            # bypass cognitive complexity check
            return get_ca(self.tsh, parsed.format)

        elif parsed.field == "cert":
            if parsed.format == "path":
                return str(self.tsh.path_cert)
            elif parsed.format == "pem":
                return self.tsh.cert.decode()

        elif parsed.field == "key":
            if parsed.format == "path":
                return str(self.tsh.path_key)
            elif parsed.format == "pem":
                return self.tsh.key.decode()

        elif parsed.field == "cert+key":
            if parsed.format == "path":
                return str(self.tsh.path_cert_and_key)
            elif parsed.format == "pem":
                return self.tsh.cert_and_key.decode()

        raise ConfigError("Invalid value spec: {}", spec)


def parse_spec(spec: RequestSpec) -> OutputSpec:
    # extract
    if isinstance(spec, str):
        output_field = spec
        output_format = DEFAULT_OUTPUT_FORMAT
    elif isinstance(spec, dict):
        output_field = spec.get("field")
        output_format = spec.get("format", DEFAULT_OUTPUT_FORMAT)
    else:
        raise ConfigError(
            "Expect dict for secrets path spec, got {}", type(spec).__name__
        )

    # validate
    if (
        False
        or not isinstance(output_field, str)
        or output_field.lower() not in ("uri", "ca", "cert", "key", "cert+key")
    ):
        raise ConfigError("Invalid field (secrets.VAR.field): {}", output_field)

    if (
        False
        or not isinstance(output_format, str)
        or output_format.lower() not in ("path", "pem")
    ):
        raise ConfigError("Invalid format (secrets.VAR.format): {}", output_format)

    return OutputSpec(output_field.lower(), output_format.lower())  # type: ignore[reportGeneralTypeIssues]


def get_ca(
    conn_info: TeleportConnectionParameter, format_: Literal["path", "pem"]
) -> str:
    if not conn_info.ca:
        raise ValueNotFound("CA is not avaliable")
    if format_ == "path":
        return str(conn_info.path_ca)
    elif format_ == "pem":
        return conn_info.ca.decode()
    raise RuntimeError

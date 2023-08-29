import logging
import typing
from functools import cached_property
from typing import Literal, Optional

from secrets_env.exceptions import ConfigError, TypeError, ValueNotFound
from secrets_env.provider import ProviderBase
from secrets_env.providers.teleport.helper import get_connection_info

if typing.TYPE_CHECKING:
    from secrets_env.provider import RequestSpec
    from secrets_env.providers.teleport.helper import AppConnectionInfo

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

    def __init__(
        self,
        *,
        proxy: Optional[str],
        cluster: Optional[str],
        user: Optional[str],
        app: str,
    ) -> None:
        self.proxy = proxy
        self.cluster = cluster
        self.user = user
        self.app = app

    @cached_property
    def tsh(self) -> "AppConnectionInfo":
        """Return teleport app connection information."""
        return get_connection_info(
            {
                "proxy": self.proxy,
                "cluster": self.cluster,
                "user": self.user,
                "app": self.app,
            }
        )

    def get(self, raw_spec: "RequestSpec") -> str:
        spec = parse_spec(raw_spec)

        if spec.field == "uri":
            return self.tsh.uri

        elif spec.field == "ca":
            # bypass cognitive complexity check
            return get_ca(self.tsh, spec.format)

        elif spec.field == "cert":
            if spec.format == "path":
                return str(self.tsh.path_cert)
            elif spec.format == "pem":
                return self.tsh.cert.decode()

        elif spec.field == "key":
            if spec.format == "path":
                return str(self.tsh.path_key)
            elif spec.format == "pem":
                return self.tsh.key.decode()

        elif spec.field == "cert+key":
            if spec.format == "path":
                return str(self.tsh.path_cert_and_key)
            elif spec.format == "pem":
                return self.tsh.cert_and_key.decode()

        raise ConfigError("Invalid value spec: {}", raw_spec)


def parse_spec(spec: "RequestSpec") -> OutputSpec:
    # extract
    if isinstance(spec, str):
        output_field = spec
        output_format = DEFAULT_OUTPUT_FORMAT
    elif isinstance(spec, dict):
        output_field = spec.get("field")
        output_format = spec.get("format", DEFAULT_OUTPUT_FORMAT)
    else:
        raise TypeError("secret path spec", dict, spec)

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

    return OutputSpec(output_field.lower(), output_format.lower())  # type: ignore


def get_ca(conn_info: "AppConnectionInfo", format_: Literal["path", "pem"]) -> str:
    if not conn_info.ca:
        raise ValueNotFound("CA is not avaliable")
    if format_ == "path":
        return str(conn_info.path_ca)
    elif format_ == "pem":
        return conn_info.ca.decode()
    raise RuntimeError

import typing
from typing import Dict, NamedTuple, TypedDict

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.auth import Auth


class SecretPath(NamedTuple):
    path: str
    field: str


class TLSConfig(TypedDict):
    ca_cert: "Path"
    client_cert: "Path"
    client_key: "Path"


class Config(NamedTuple):
    url: str
    auth: "Auth"
    tls: TLSConfig
    secret_specs: Dict[str, SecretPath]

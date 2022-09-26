import typing
from typing import Dict, Literal, NamedTuple, Optional, TypedDict

if typing.TYPE_CHECKING:
    from pathlib import Path

    from secrets_env.auth import Auth


class ConfigFileMetadata(NamedTuple):
    filename: str
    spec: Literal["json", "yaml", "toml", "pyproject.toml"]
    enable: bool
    path: Optional["Path"] = None

    @property
    def lang(self) -> str:
        return {
            "json": "JSON",
            "yaml": "YAML",
            "toml": "TOML",
            "pyproject.toml": "TOML",
        }.get(self.spec)


class SecretPath(NamedTuple):
    path: str
    key: str


class TLSConfig(TypedDict):
    ca_cert: "Path"
    client_cert: "Path"
    client_key: "Path"


class Config(NamedTuple):
    url: str
    auth: "Auth"
    tls: TLSConfig
    secret_specs: Dict[str, SecretPath]

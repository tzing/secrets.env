from typing import TYPE_CHECKING, Dict, Literal, NamedTuple, Optional

if TYPE_CHECKING:
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


class TLSConfig(NamedTuple):
    ca_cert: Optional["Path"]
    client_cert: Optional["Path"]
    client_key: Optional["Path"]


class Config(NamedTuple):
    url: str
    auth: "Auth"
    tls: Optional[TLSConfig]
    secret_specs: Dict[str, SecretPath]

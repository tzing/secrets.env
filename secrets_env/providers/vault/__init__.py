from secrets_env.exceptions import ConfigError

from .config import get_connection_info
from .provider import KvProvider


def get_provider(type_: str, data: dict) -> KvProvider:
    if not (cfg := get_connection_info(data)):
        raise ConfigError("Invalid config for vault provider")
    return KvProvider(**cfg)

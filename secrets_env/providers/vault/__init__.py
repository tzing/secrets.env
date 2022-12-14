from typing import Optional

from secrets_env.exceptions import ConfigError
from secrets_env.providers.vault.config import get_connection_info
from secrets_env.providers.vault.provider import KvProvider


def get_provider(type_: str, data: dict) -> Optional[KvProvider]:
    if type_ != "vault":
        return None
    if not (cfg := get_connection_info(data)):
        raise ConfigError("Invalid config for vault provider")
    return KvProvider(**cfg)

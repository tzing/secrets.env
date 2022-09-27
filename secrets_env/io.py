import os
from typing import Optional

import keyring
import keyring.errors


def get_env_var(*names: str) -> Optional[str]:
    """Get value from (any candidate) environment variable."""
    for name in names:
        if var := os.getenv(name):
            return var
    return None


def read_keyring(name: str) -> Optional[str]:
    """Wrapped `keyring.get_password`. Do not raise error when there is no
    keyring backend enabled."""
    try:
        return keyring.get_password("secrets.env", name)
    except keyring.errors.NoKeyringError:
        return None

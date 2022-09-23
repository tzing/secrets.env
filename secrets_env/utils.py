import os
from typing import Optional


def get_env_var(*names: str) -> Optional[str]:
    """Get value from environment variable. Accepts multiple names."""
    for name in names:
        if var := os.getenv(name):
            return var
    return None

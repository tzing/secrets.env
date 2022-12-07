import logging
from typing import Any, Dict, Optional, Tuple, TypedDict, Union

from secrets_env.io import get_env_var
from secrets_env.utils import ensure_dict, ensure_path, ensure_str

logger = logging.getLogger(__name__)


def get_url(data: dict) -> Optional[str]:
    url = get_env_var("SECRETS_ENV_ADDR", "VAULT_ADDR")
    if not url:
        url = data.get("url", None)

    if not url:
        logger.error(
            "Missing required config <mark>url</mark>. "
            "Please provide from config file (<mark>source.url</mark>) "
            "or environment variable (<mark>SECRETS_ENV_ADDR</mark>)."
        )
        return None

    url, ok = ensure_str("source.url", url)
    if not ok:
        return None

    return url

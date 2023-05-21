import logging
from typing import Any, Dict, Optional, TypedDict

from secrets_env.exceptions import ConfigError
from secrets_env.utils import ensure_dict, ensure_str

logger = logging.getLogger()


class AppParameter(TypedDict):
    """Parameters used for retrieving app certificates."""

    proxy: Optional[str]
    user: Optional[str]
    app: str


def parse_config(data: Dict[str, Any]) -> AppParameter:
    section = data.get("teleport")
    if not section:
        raise ConfigError("Missing 'teleport' config")

    # case: short cut
    if isinstance(section, str):
        section = {"app": section}

    # get parameters
    section, _ = ensure_dict("source.teleport", section)

    if proxy := section.get("proxy"):
        proxy, _ = ensure_str("source.teleport.proxy", proxy)
    if user := section.get("user"):
        user, _ = ensure_str("source.teleport.user", user)

    app, ok = ensure_str("source.teleport.app", section.get("app"))
    if not ok:
        raise ConfigError("Invalid config for Teleport integration")

    return AppParameter(
        proxy=proxy,
        user=user,
        app=app,  # type: ignore[reportOptionalMemberAccess]
    )

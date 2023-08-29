import logging
import typing
from typing import Any, Dict, Optional, TypedDict, Union

from secrets_env.exceptions import ConfigError
from secrets_env.utils import ensure_dict, ensure_str

logger = logging.getLogger()


class AppParameter(TypedDict):
    """Parameters used for retrieving app certificates."""

    proxy: Optional[str]
    cluster: Optional[str]
    user: Optional[str]
    app: str


def parse_source_config(data: Dict[str, Any]) -> AppParameter:
    return parse_config("source", data)


def parse_adapter_config(data: Dict[str, Any]) -> AppParameter:
    section = data.get("teleport")
    if not section:
        raise ConfigError("Missing 'teleport' config")
    return parse_config("source.teleport", section)


def parse_config(prefix: str, section: Union[Dict[str, Any], str]) -> AppParameter:
    # short cut
    if isinstance(section, str):
        section = {"app": section}

    # get parameters
    section, _ = ensure_dict(prefix, section)

    if proxy := section.get("proxy"):
        proxy, _ = ensure_str(f"{prefix}.proxy", proxy)
    if cluster := section.get("cluster"):
        cluster, _ = ensure_str(f"{prefix}.cluster", cluster)
    if user := section.get("user"):
        user, _ = ensure_str(f"{prefix}.user", user)

    app, ok = ensure_str(f"{prefix}.app", section.get("app"))
    if not ok:
        raise ConfigError("Invalid config for Teleport integration")

    return AppParameter(
        proxy=proxy,
        cluster=cluster,
        user=user,
        app=typing.cast(str, app),
    )

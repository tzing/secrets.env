import itertools
import logging
import re
import typing
from typing import Any, Dict, Iterator, List, Optional, Tuple, TypedDict

import secrets_env.exceptions
import secrets_env.providers
from secrets_env.provider import RequestSpec
from secrets_env.utils import ensure_dict, ensure_str

if typing.TYPE_CHECKING:
    from secrets_env.provider import ProviderBase

DEFAULT_PROVIDER_NAME = "main"

logger = logging.getLogger(__name__)


class Request(TypedDict):
    """:py:class:`Request` for loading secret value. Secrets.env would fetch
    the secret value from the provider and load it into environment."""

    name: str
    provider: str
    spec: RequestSpec


class Config(TypedDict):
    """The parsed configurations."""

    providers: Dict[str, "ProviderBase"]
    requests: List[Request]


def parse_config(data: dict) -> Optional[Config]:
    """Parse and validate configs, build it into structured object."""
    requests = get_requests(data)
    if not requests:
        logger.info("No request specificied.")
        return None

    providers = get_providers(data)
    if not providers:
        logger.error("Secret provider config error")
        return None

    return Config(providers=providers, requests=requests)


def get_providers(data: dict) -> Dict[str, "ProviderBase"]:
    sections = list(extract_sources(data))
    logger.debug("%d raw provider configs extracted", len(sections))

    providers: Dict[str, "ProviderBase"] = {}
    for data in sections:
        result = parse_source_item(data)
        if not result:
            continue

        name, provider = result

        # name should be unique
        if name in providers:
            logger.error(
                "Duplicated source name <data>%s</data>. Discard the later one.",
                name,
            )
            continue

        # save
        providers[name] = provider

    logger.debug("%d valid provider(s) created", len(providers))
    return providers


def extract_sources(data: dict) -> Iterator[Dict[str, Any]]:
    """Extracts both "source(s)" section and ensure the output is list of dict"""
    for item in itertools.chain(
        get_list(data, "source"),
        get_list(data, "sources"),
    ):
        cfg, ok = ensure_dict("source", item)
        if ok:
            yield cfg


def get_list(data: dict, key: str) -> Iterator[dict]:
    """Get item from the dict, ensure output is list"""
    item = data.get(key, [])
    if isinstance(item, dict):
        yield item
    elif isinstance(item, list):
        yield from item
    else:
        logger.warning("Found invalid value in field <mark>%s</mark>", key)


def parse_source_item(config: dict) -> Optional[Tuple[str, "ProviderBase"]]:
    # check name
    name = config.get("name") or DEFAULT_PROVIDER_NAME
    name, ok = ensure_str("source.name", name)
    if not ok or not name:
        return None

    # get provider
    try:
        provider = secrets_env.providers.get_provider(config)
    except secrets_env.exceptions.AuthenticationError as e:
        logger.error("Authentication error: %s", e)
        return None
    except secrets_env.exceptions.ConfigError as e:
        logger.error("Configuration error: %s", e)
        return None

    return name, provider


def get_requests(data: dict) -> List[Request]:
    # accept both keyword `secret(s)`
    raw = {}

    raw.update(get_dict(data, "secret"))
    raw.update(get_dict(data, "secrets"))
    logger.debug("%d raw secret requests extracted", len(raw))

    # validate and load
    output = []
    for name, data in raw.items():
        if not is_valid_var_name(name):
            logger.warning("Invalid name <data>%s</data>.", name)
            continue

        if isinstance(data, str):
            output.append(
                Request(
                    name=name,
                    provider=DEFAULT_PROVIDER_NAME,
                    spec=data,
                )
            )

        elif isinstance(data, dict):
            output.append(
                Request(
                    name=name,
                    provider=data.get("source") or DEFAULT_PROVIDER_NAME,
                    spec=data,
                )
            )

        else:
            logger.warning("Invalid spec type for variable <data>%s</data>.", name)

    logger.debug("%d valid secret request(s) parsed", len(output))
    return output


def get_dict(data: dict, key: str) -> dict:
    if d := data.get(key):
        d, ok = ensure_dict(key, d)
        if ok:
            return d
    return {}


__regex_var_name = None


def is_valid_var_name(s: str) -> bool:
    global __regex_var_name
    if not __regex_var_name:
        __regex_var_name = re.compile(
            r"[a-z_][a-z0-9_]*", re.RegexFlag.ASCII | re.RegexFlag.IGNORECASE
        )
    match_ = __regex_var_name.fullmatch(s)
    return bool(match_)

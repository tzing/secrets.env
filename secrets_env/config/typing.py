import logging
from typing import Any, Optional, Tuple, TypeVar

T = TypeVar("T")

logger = logging.getLogger(__name__)


def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: type,
    cast: bool,
    default: T,
) -> Tuple[T, bool]:
    """Check if the given value is the expected type, fallback to default value
    when false."""
    # returns ok if already the desired type
    if isinstance(value, expect_type):
        return value, True

    # try type casting
    if cast:
        try:
            return expect_type(value), True
        except Exception:
            ...

    # show warning and returns default value
    logger.warning(
        "Expect <mark>%s</mark> type for config <mark>%s</mark>, "
        "got <data>%s</data> (<mark>%s</mark> type)",
        type_name,
        value_name,
        trimmed_str(value),
        type(value).__name__,
    )
    return default, False


def ensure_str(name: str, s: Any) -> Tuple[Optional[str], bool]:
    return ensure_type(name, s, "str", str, False, None)


def ensure_dict(name: str, d: Any) -> Tuple[dict, bool]:
    return ensure_type(name, d, "dict", dict, False, {})


def trimmed_str(o: Any) -> str:
    """Cast an object to str and trimmed."""
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

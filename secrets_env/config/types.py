import logging
from pathlib import Path
from typing import Any, Literal, Optional, Tuple, Type, TypeVar, Union, overload

T = TypeVar("T")
TL_True = Literal[True]
TL_False = Literal[False]

logger = logging.getLogger(__name__)


@overload
def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: Type[T],
    cast: bool,
    default: T,
) -> Union[Tuple[T, TL_True], Tuple[T, TL_False]]:
    ...  # pragma: no cover


@overload
def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: Type[T],
    cast: bool,
) -> Union[Tuple[T, TL_True], Tuple[Literal[None], TL_False]]:
    ...  # pragma: no cover


def ensure_type(
    value_name: str,
    value: Any,
    type_name: str,
    expect_type: Type[T],
    cast: bool,
    default: Optional[T] = None,
) -> Union[Tuple[T, TL_True], Tuple[Optional[T], TL_False]]:
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


def ensure_str(name: str, s: Any) -> Union[Tuple[str, TL_True], Tuple[None, TL_False]]:
    return ensure_type(name, s, "str", str, False)


def ensure_dict(name: str, d: Any) -> Tuple[dict, bool]:
    return ensure_type(name, d, "dict", dict, False, {})


def ensure_path(
    name: str, p: Any, is_file: bool = True
) -> Union[Tuple[Path, TL_True], Tuple[None, TL_False]]:
    path: Optional[Path]
    path, _ = ensure_type(name, p, "path", Path, True)
    if not path:
        return None, False

    if is_file and not path.is_file():
        logger.warning(
            "Expect valid path for config <mark>%s</mark>: "
            "file <data>%s</data> not exists",
            name,
            path,
        )
        return None, False

    return path, True


def trimmed_str(o: Any) -> str:
    """Cast an object to str and trimmed."""
    __max_len = 20
    s = str(o)
    if len(s) > __max_len:
        s = s[: __max_len - 3] + "..."
    return s

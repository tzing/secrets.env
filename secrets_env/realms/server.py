"""
Minimal multi-threaded HTTP server and request handler, with thread-safe context storage.

Use :meth:`start_server` to start a HTTP server in a background thread, then
share information among threads using :attr:`ThreadingHTTPServer.context`.
"""

from __future__ import annotations

import collections.abc
import contextlib
import http.server
import logging
import socket
import threading
import typing
import urllib.parse
from http import HTTPStatus
from typing import Any

from secrets_env.utils import get_template

if typing.TYPE_CHECKING:
    from typing import Callable, Iterator

    URLParams = dict[str, list[str]]
    RouteHandler = Callable[[URLParams], None]

logger = logging.getLogger(__name__)


class RwLock:
    """Readers-writer lock."""

    def __init__(self) -> None:
        self.write_lock = threading.Lock()
        self._read_counter_lock = threading.Lock()
        self._read_counter = 0

    def read_lock_acquire(self):
        with self._read_counter_lock:
            self._read_counter += 1
            if self._read_counter == 1:
                self.write_lock.acquire()

    def read_lock_release(self):
        with self._read_counter_lock:
            self._read_counter -= 1
            if self._read_counter == 0:
                self.write_lock.release()

    @property
    @contextlib.contextmanager
    def read_lock(self):
        self.read_lock_acquire()
        try:
            yield
        finally:
            self.read_lock_release()


class ThreadSafeDict(collections.abc.MutableMapping[str, Any]):
    """A :class:`dict` with read-write lock."""

    def __init__(self) -> None:
        self._lock = RwLock()
        self._data: dict = {}

    def __repr__(self) -> str:
        with self._lock.read_lock:
            return repr(self._data)

    def __getitem__(self, __key: str) -> Any:
        with self._lock.read_lock:
            return self._data.__getitem__(__key)

    def __setitem__(self, __key: str, __value: Any) -> None:
        with self._lock.write_lock:
            return self._data.__setitem__(__key, __value)

    def __delitem__(self, __key: str) -> None:
        with self._lock.write_lock:
            return self._data.__delitem__(__key)

    def __iter__(self) -> Iterator[str]:
        with self._lock.read_lock:
            return iter(self._data)

    def __len__(self) -> int:
        with self._lock.read_lock:
            return len(self._data)

    def __contains__(self, __key: object) -> bool:
        with self._lock.read_lock:
            return __key in self._data


def get_free_port() -> int:
    """Get a free port from the system."""
    with socket.socket() as s:
        s.bind(("", 0))
        _, port = s.getsockname()
    return port

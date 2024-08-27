"""
Minimal multi-threaded HTTP server and request handler, with thread-safe context storage.

Use :meth:`start_server` to start a HTTP server in a background thread, then
share information among threads using :attr:`ThreadedHttpServer.context`.
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


def start_server(
    handler: type[HttpRequestHandler],
    host: str = "127.0.0.1",
    port: int | None = None,
    *,
    auto_ready: bool = True,
) -> ThreadedHttpServer:
    """
    Starts a :py:class:`ThreadedHttpServer` that listen to the specified
    port.

    Parameters
    ----------
    handler : type[HttpRequestHandler]
        Request handler class.
    host : str
        The address on which the server is listening.
    port : int
        The port to listen to. It uses random port when not set.
    auto_ready : bool
        Set the server as *ready to start* automatically. When :obj:`False`, the
        server thread will not start serving requests until :attr:`ThreadedHttpServer.ready`
        event is set.

    Return
    ------
    server : ThreadedHttpServer
    """
    if port is None:
        port = get_free_port()

    server = ThreadedHttpServer.create(host=host, port=port, handler=handler)

    if auto_ready:
        server.ready.set()

    return server


class ThreadedHttpServer(http.server.ThreadingHTTPServer):
    """
    A HTTP server that runs in background thread, creates threads for every
    response and provide a shared context storage.
    """

    context: ThreadSafeDict
    """A dictionary to share information among threads."""

    ready: threading.Event
    """An event object to notify the background thread that setup is finished."""

    server_thread: threading.Thread
    """The thread that runs this server."""

    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        handler: type[HttpRequestHandler],
    ):
        """
        Create a HTTP server that served in background thread.

        The background thread starts automatically but will not serve requests
        until :attr:`ready` event is set.

        .. tip::

           Consider using the :func:`start_server` method for a more straightforward
           approach to achieve the same purpose.

        Parameters
        ----------
        host : str
            The address on which the server is listening.
        port : int
            The port to listen to.
        handler : HttpRequestHandler
            Request handler class.
        """
        server = cls(server_address=(host, port), RequestHandlerClass=handler)

        server.context = ThreadSafeDict()
        server.ready = threading.Event()
        server.server_thread = threading.Thread(target=server._worker_, daemon=True)

        server.server_thread.start()
        return server

    def _worker_(self):
        """
        Background runner for the server thread.
        """
        logger.debug(
            "HTTP server thread created. thread id= %s; address= %s",
            threading.get_native_id(),
            self.server_address,
        )

        # wait until setup finish
        self.ready.wait()

        # listening
        logger.debug("Start listening %s", self.server_address)
        with self:
            self.serve_forever()

        # finalize
        logger.debug(
            "HTTP Server shutdown. thread id= %s; address= %s",
            threading.get_native_id(),
            self.server_address,
        )

    @property
    def server_url(self) -> str:
        """Returns server URL."""
        host, port = self.server_address
        return f"http://{host}:{port}"


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

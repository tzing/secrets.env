import abc
import collections.abc
import contextlib
import http.server
import logging
import pathlib
import socket
import threading
import typing
import urllib.parse
from http import HTTPStatus
from typing import Any, Callable, Dict, Iterator, List, Optional

URLParams = Dict[str, List[str]]
RouteHandler = Callable[[URLParams], None]

logger = logging.getLogger(__name__)


class RWLock:
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


class SafeDict(collections.abc.MutableMapping[str, Any]):
    """Dictionary with read write lock."""

    def __init__(self) -> None:
        self._lock = RWLock()
        self._data: Dict = {}

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


class HTTPRequestHandler(abc.ABC, http.server.SimpleHTTPRequestHandler):
    server: "HTTPServer"

    @abc.abstractmethod
    def route(self, path: str) -> Optional["RouteHandler"]:
        """Routing GET request to specific method."""

    def do_GET(self) -> None:
        # parse path
        url = urllib.parse.urlsplit(self.path)
        logger.debug('Receive "%s %s %s"', self.command, url.path, self.request_version)

        # check routes
        func = self.route(url.path)
        if func is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        # parse parameters and callback
        params = urllib.parse.parse_qs(url.query)
        return func(params)

    def log_message(self, fmt: str, *args: Any) -> None:
        """Redirect request logs to logging infrastructure, while the builtin
        implementation writes data to stderr."""
        logger.debug(
            "%s - - [%s] %s",
            self.address_string(),
            self.log_date_time_string(),
            fmt % args,
        )

    def write_template(self, template: str):
        """Write template data to response body."""
        current_dir = pathlib.Path(__file__).resolve().parent
        template_dir = current_dir / "templates"
        template_file = template_dir / template

        payload = template_file.read_bytes()
        self.wfile.write(payload)


class HTTPServer(http.server.ThreadingHTTPServer):
    """A HTTP server with a shared context dict"""

    context: SafeDict
    """A dictionary to share information among threads."""

    ready: threading.Event

    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        handler: typing.Type[HTTPRequestHandler],
    ):
        """Create a :py:class:`http.server.HTTPServer` and add context dict.

        :py:class:`socketserver.TCPServer` says never override its constructor so
        the context object would be set after initialize.
        """
        server = cls(server_address=(host, port), RequestHandlerClass=handler)

        # HTTPServer property
        server.allow_reuse_address = True

        # customized
        server.context = SafeDict()
        server.ready = threading.Event()

        return server

    @property
    def server_uri(self):
        host, port = self.server_address
        self.server_name
        return f"http://{host}:{port}"


class HTTPServerThread(threading.Thread):
    def __init__(
        self,
        host: str,
        port: int,
        handler: typing.Type[HTTPRequestHandler],
    ) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.handler = handler

        self.server: Optional[HTTPServer] = None

        self.initialized = threading.Event()

    def run(self) -> None:
        with HTTPServer.create(self.host, self.port, self.handler) as srv:
            self.server = srv
            self.initialized.set()

            logger.debug("HTTP server created. Waiting for setup...")
            srv.ready.wait()

            logger.debug("Start listening %s", srv.server_address)
            srv.serve_forever()

        logger.debug("Stop listen %s", srv.server_address)


def start_server(
    handler: typing.Type[HTTPRequestHandler],
    host: str = "127.0.0.1",
    port: Optional[int] = None,
    need_prepare: bool = False,
) -> HTTPServer:
    if port is None:
        port = get_free_port()

    # start background thread
    thread = HTTPServerThread(host, port, handler)
    thread.start()

    # get server instance
    thread.initialized.wait()
    assert thread.server
    server = thread.server

    # prepare
    if not need_prepare:
        server.ready.set()

    return server


def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        _, port = s.getsockname()
    return port

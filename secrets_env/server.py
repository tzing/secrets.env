import collections.abc
import contextlib
import functools
import http.server
import logging
import pathlib
import socket
import string
import sys
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


if sys.version_info >= (3, 9):
    _SafeDictBase = collections.abc.MutableMapping[str, Any]
else:
    _SafeDictBase = collections.abc.MutableMapping


class SafeDict(_SafeDictBase):
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


class HTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    server: "ThreadingHTTPServer"

    def route(self, path: str) -> Optional["RouteHandler"]:
        """Routing GET request to specific method."""

    def do_GET(self) -> None:
        # parse path
        url = urllib.parse.urlsplit(self.path)
        logger.debug('Receive "%s %s %s"', self.command, url.path, self.request_version)

        # check routes
        func = self.route(url.path)
        if func is None:
            self.response_error(HTTPStatus.NOT_FOUND)
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

    def response_html(self, code: int, filename: str, mapping: Optional[dict] = None):
        """Response from template."""
        # render body
        template = get_template(filename)
        body = template.safe_substitute(mapping or {})
        payload = body.encode(errors="replace")

        # response
        self.send_response(code)
        self.send_header("Content-type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()

        self.wfile.write(payload)

    def response_error(self, code: int):
        """Response error from template."""
        status = HTTPStatus(code)
        return self.response_html(
            status.value,
            "error.html",
            {"title": status.phrase, "message": status.description},
        )


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """A HTTP server that runs in background thread, creates threads for every
    response and provide a shared context storage."""

    context: SafeDict
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
        handler: typing.Type[HTTPRequestHandler],
    ):
        """Create a HTTP server that served in background thread.
        The threads starts automatically but will not serve requests until
        :py:attr:`ready` event is set.
        """
        server = cls(server_address=(host, port), RequestHandlerClass=handler)

        server.context = SafeDict()
        server.ready = threading.Event()
        server.server_thread = threading.Thread(target=server._worker, daemon=True)

        server.server_thread.start()
        return server

    def _worker(self):
        """Background runner."""
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
            "HTTP Server shutdown. ident= %s; address= %s",
            threading.get_native_id(),
            self.server_address,
        )

    @property
    def server_uri(self):
        host, port = self.server_address
        return f"http://{host}:{port}"


def start_server(
    handler: typing.Type[HTTPRequestHandler],
    host: str = "127.0.0.1",
    port: Optional[int] = None,
    *,
    ready: bool = True,
) -> ThreadingHTTPServer:
    if port is None:
        port = get_free_port()

    server = ThreadingHTTPServer.create(host=host, port=port, handler=handler)

    if ready:
        server.ready.set()

    return server


def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        _, port = s.getsockname()
    return port


@functools.lru_cache(maxsize=None)
def get_template(filename: str) -> string.Template:
    current_dir = pathlib.Path(__file__).resolve().parent
    template_dir = current_dir / "templates"
    template_file = template_dir / filename

    content = template_file.read_text()
    template = string.Template(content)

    return template

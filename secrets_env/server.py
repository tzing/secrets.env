import abc
import http.server
import logging
import socket
import threading
import typing
import urllib.parse
from http import HTTPStatus
from typing import Any, Callable, Dict, List, Literal, Optional

DEFAULT_SERVER_LOOP_TIMEOUT = 0.08

URLParam = Dict[str, List[str]]
RouteHandler = Callable[[URLParam], None]

logger = logging.getLogger(__name__)


class HTTPRequestHandler(abc.ABC, http.server.SimpleHTTPRequestHandler):
    server: "HTTPServer"

    @abc.abstractmethod
    def route(self, method: Literal["GET"], path: str) -> Optional[RouteHandler]:
        """Routing GET request to specific method."""

    def do_GET(self) -> None:
        # parse path
        url = urllib.parse.urlsplit(self.path)
        logger.debug('Receive "%s %s %s"', self.command, url.path, self.request_version)

        # check routes
        func = self.route("GET", url.path)
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


class HTTPServer(http.server.HTTPServer):
    """A HTTP server with a shared context dict"""

    context: Dict[str, Any]
    """A dictionary to share information among threads."""

    ready: threading.Event
    stop: threading.Event

    @classmethod
    def create(
        cls,
        host: str,
        port: int,
        handler: typing.Type[HTTPRequestHandler],
        timeout=DEFAULT_SERVER_LOOP_TIMEOUT,
    ):
        """Create a :py:class:`http.server.HTTPServer` and add context dict.

        :py:class:`socketserver.TCPServer` says never override its constructor so
        the context object would be set after initialize.
        """
        server = cls(server_address=(host, port), RequestHandlerClass=handler)
        server.timeout = timeout
        server.context = {}
        server.ready = threading.Event()
        server.stop = threading.Event()
        return server


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

            logger.debug("Start listening %s:%d", srv.server_name, srv.server_port)
            while not srv.stop.is_set():
                srv.handle_request()

        logger.debug("Stop listen %s:%d", self.host, self.port)


def start_server(
    handler: typing.Type[HTTPRequestHandler],
    host: str = "localhost",
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

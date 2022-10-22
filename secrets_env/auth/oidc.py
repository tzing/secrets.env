import http.server
import logging
import socket
import threading
import typing
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional

from secrets_env.auth.base import Auth
from secrets_env.exception import TypeError

if typing.TYPE_CHECKING:
    import hvac
    import hvac.adapters

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenIDConnectAuth(Auth):
    role: Optional[str]
    """Role.
    """

    authorization_code: str = field(repr=False)
    """Authorization code from server response."""

    def __init__(self, role: Optional[str] = None) -> None:
        super().__init__()
        if role is not None and not isinstance(role, str):
            raise TypeError("Expect str for role, got {}", type(role).__name__)
        object.__setattr__(self, "role", role)

    @classmethod
    def method(cls) -> str:
        return "oidc"

    def apply(self, client: "hvac.Client"):
        logger.debug("Applying ODIC auth")

        # start server for receiving callback
        port = get_free_port()
        server_thread = self.start_server(port)

        # TODO open the link
        # FIXME the builtin one is lack of error handling

        logger.info("<!important>Waiting for response from OIDC provider...")
        logger.info(
            "<!important>If browser does not open automatically, open the link:"
        )
        logger.info("<!important>  %s", auth_url)
        webbrowser.open(auth_url)

    def start_server(self, port: int):
        """Starting a HTTP server locally and waiting for the authentication code."""
        stop_event = threading.Event()

        def _set_code(code: str) -> None:
            object.__setattr__(self, "authorization_code", code)

        class _Handler(OpenIDConnectCallbackHandler):
            def finalize(self, code: str):
                nonlocal stop_event, _set_code
                _set_code(code)
                stop_event.set()

        def _worker(event: threading.Event):
            global logger
            with http.server.HTTPServer(("localhost", port), _Handler) as srv:
                logger.debug("Start listening port %d for OIDC response", port)
                while not event.is_set():
                    srv.handle_request()

        thread = threading.Thread(target=_worker, args=(stop_event,), daemon=True)
        thread.start()

        return thread

    def load(self):
        ...


class OpenIDConnectCallbackHandler(http.server.SimpleHTTPRequestHandler):
    CALLBACK_PATH = "/oidc/callback"

    def do_GET(self) -> None:
        """Handles GET request."""
        url = urllib.parse.urlsplit(self.path)
        if url.path != self.CALLBACK_PATH:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        params = urllib.parse.parse_qs(url.query)
        code, *_ = params.get("code", [None])
        if not code:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=UTF-8")
        self.end_headers()
        self.wfile.write(b"Authentication successful, you can close the browser now.")

        self.finalize(code)

    def finalize(self, code: str) -> None:
        """Successfully received the authorization code. Notify for stop serving."""
        raise NotImplementedError()


def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        _, port = s.getsockname()
    return port


def get_oidc_authorization_url(
    adapter: "hvac.adapters.Adapter", redirect_uri: str, role: Optional[str]
):
    """Get OIDC authorization URL.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/jwt#oidc-authorization-url-request
    """
    data = {"redirect_uri": redirect_uri}
    if role:
        data["role"] = role

    return adapter.post(
        "/v1/auth/jwt/oidc/auth_url", data=data
    )  # FIXME must extract data from it

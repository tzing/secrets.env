import http.server
import logging
import socket
import threading
import typing
import urllib.parse
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional

from secrets_env.auth.base import Auth
from secrets_env.exception import AuthenticationError, TypeError

if typing.TYPE_CHECKING:
    import httpx

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

    def login(self, client: "httpx.Client") -> str:
        logger.debug("Applying ODIC auth")

        # start server for receiving callback
        port = get_free_port()
        server_thread, stop_event = self.start_server(port)

        # request for auth url
        nonce = uuid.uuid1().hex
        auth_url = get_oidc_authorization_url(
            client,
            f"http://localhost:{port}{OpenIDConnectCallbackHandler.CALLBACK_PATH}",
            self.role,
            nonce,
        )

        # open the link
        logger.info("<!important>Waiting for response from OpenID connect provider...")
        logger.info(
            "<!important>If browser does not open automatically, open the link:"
        )
        logger.info("<!important>  %s", auth_url)
        webbrowser.open(auth_url)

        # wait until callback
        try:
            server_thread.join()
        except KeyboardInterrupt:
            raise AuthenticationError("keyboard interrupted")
        finally:
            stop_event.set()

        # TODO call second URL

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

        return thread, stop_event

    def load(self):
        raise NotImplementedError()


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
    client: "httpx.Client", redirect_uri: str, role: Optional[str], nonce: str
) -> Optional[str]:
    """Get OIDC authorization URL.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/jwt#oidc-authorization-url-request
    """
    data = {
        "redirect_uri": redirect_uri,
        "client_nonce": nonce,
    }
    if role:
        data["role"] = role

    resp = client.post("/v1/auth/oidc/oidc/auth_url", json=data)

    if resp.status_code == HTTPStatus.OK:
        data = resp.json()
        return data["data"]["auth_url"]

    logger.error("Error requesting authorization URL")
    logger.debug("Code= %d. Raw response= %s", resp.status_code, resp.text)
    return None

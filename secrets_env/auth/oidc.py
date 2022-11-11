import logging
import socket
import threading
import typing
import urllib.parse
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Optional

from secrets_env.auth.base import Auth
from secrets_env.exception import AuthenticationError, TypeError

if typing.TYPE_CHECKING:
    import httpx

SERVER_LOOP_TIMEOUT = 0.08

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OpenIDConnectAuth(Auth):
    role: Optional[str]
    """Role.
    """

    authorization_code: str = field(repr=False, default=None)
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

        # prepare data for callback server
        port = get_free_port()
        client_nonce = uuid.uuid1().hex

        # request for auth url
        auth_url = get_oidc_authorization_url(
            client,
            f"http://localhost:{port}{OpenIDConnectCallbackHandler.CALLBACK_PATH}",
            self.role,
            client_nonce,
        )

        if not auth_url:
            raise AuthenticationError("Failed to get OIDC authorization URL")

        # start callback server
        server_thread = OpenIDConnectCallbackService(port, self)
        server_thread.start()

        # open the link
        logger.info(
            "<!important>"
            "Waiting for response from OpenID connect provider...\n"
            "If browser does not open automatically, open the link:\n"
            f"  {auth_url}"
        )
        webbrowser.open(auth_url)

        # wait until callback
        try:
            server_thread.join()
        finally:
            server_thread.shutdown_server()

        if not self.authorization_code:
            raise AuthenticationError("OIDC Authorization code not received")

        # get client token
        token = get_client_token(
            client, auth_url, self.authorization_code, client_nonce
        )
        if not token:
            raise AuthenticationError("Failed to fetch OIDC client token")

        return token

    def load(self):
        raise NotImplementedError()


class OpenIDConnectCallbackHandler(SimpleHTTPRequestHandler):
    CALLBACK_PATH = "/oidc/callback"

    def do_GET(self) -> None:
        """Handles GET request."""
        # parse path
        url = urllib.parse.urlsplit(self.path)
        logger.debug('Receive "%s %s %s"', self.command, url.path, self.request_version)

        # only accepts callback path
        if url.path != self.CALLBACK_PATH:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        # send http 400 if 'code' does not provided
        params = urllib.parse.parse_qs(url.query)
        code, *_ = params.get("code", [None])
        if not code:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        # save token
        self.server.auth_token = code

        # response
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=UTF-8")
        self.end_headers()
        self.wfile.write(b"Authentication successful, you can close the browser now.")


class OpenIDConnectCallbackService(threading.Thread):
    def __init__(self, port: int, storage: OpenIDConnectAuth) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.storage = storage
        self._stop_event = threading.Event()

    def run(self) -> None:
        """Run a http server in background thread."""
        logger.debug("Start listening port %d for OIDC callback", self.port)

        # serve until stop event is set
        with HTTPServer(
            server_address=("localhost", self.port),
            RequestHandlerClass=OpenIDConnectCallbackHandler,
        ) as srv:
            srv.timeout = SERVER_LOOP_TIMEOUT
            srv.auth_token = None

            while not srv.auth_token and not self._stop_event.is_set():
                srv.handle_request()

        logger.debug("Stopping OIDC callback server")

        # finalize; set auth code
        if srv.auth_token:
            object.__setattr__(self.storage, "authorization_code", srv.auth_token)

    def shutdown_server(self):
        """Shutdown internal http server."""
        logger.debug("Shutdown OIDC callback server")
        self._stop_event.set()


def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        _, port = s.getsockname()
    return port


def get_oidc_authorization_url(
    client: "httpx.Client", redirect_uri: str, role: Optional[str], client_nonce: str
) -> Optional[str]:
    """Get OIDC authorization URL.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/jwt#oidc-authorization-url-request
    """
    payload = {
        "redirect_uri": redirect_uri,
        "client_nonce": client_nonce,
    }
    if role:
        payload["role"] = role

    resp = client.post("/v1/auth/oidc/oidc/auth_url", json=payload)

    if resp.status_code == HTTPStatus.OK:
        data = resp.json()
        return data["data"]["auth_url"]

    logger.error("Error requesting authorization URL")
    logger.debug("Code= %d. Raw response= %s", resp.status_code, resp.text)
    return None


def get_client_token(
    client: "httpx.Client", auth_url: str, auth_code: str, client_nonce: str
):
    """Call OIDC callback and get the client token.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/jwt#oidc-callback
    """
    # extract server-provided metadata
    url = urllib.parse.urlsplit(auth_url)
    params = urllib.parse.parse_qs(url.query)
    server_state = params["state"][0]
    server_nonce = params["nonce"][0]

    # call oidc callback
    resp = client.get(
        "/v1/auth/oidc/oidc/callback",
        params={
            "state": server_state,
            "nonce": server_nonce,
            "code": auth_code,
            "client_nonce": client_nonce,
        },
    )

    # parse result
    if resp.status_code == HTTPStatus.OK:
        data = resp.json()
        return data["auth"]["client_token"]

    logger.error("Error requesting OIDC callback URL")
    logger.debug("Code= %d. Raw response= %s", resp.status_code, resp.text)
    return None

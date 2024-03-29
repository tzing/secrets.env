from __future__ import annotations

import logging
import typing
import urllib.parse
import uuid
import webbrowser
from http import HTTPStatus

from secrets_env.exceptions import AuthenticationError
from secrets_env.providers.vault.auth.base import Auth
from secrets_env.server import HTTPRequestHandler, start_server
from secrets_env.utils import get_env_var

if typing.TYPE_CHECKING:
    from typing import Any

    import httpx

    from secrets_env.server import RouteHandler, URLParams

PATH_OIDC_CALLBACK = "/oidc/callback"

logger = logging.getLogger(__name__)


class OpenIDConnectAuth(Auth):
    """OpenID Connect."""

    method = "OIDC"

    role: str | None
    """Role."""

    @classmethod
    def create(cls, url: Any, config: dict) -> OpenIDConnectAuth:
        if role := get_env_var("SECRETS_ENV_ROLE"):
            logger.debug("Found OIDC role from environment variable: %s", role)
            return cls(role=role)

        if role := config.get("role"):
            logger.debug("Found OIDC role from config file: %s", role)
            return cls(role=role)

        logger.debug("Missing OIDC role. Use default.")
        return cls(role=None)

    def login(self, client: httpx.Client) -> str:
        logger.debug("Applying ODIC auth")

        # prepare server
        server = start_server(OIDCRequestHandler, ready=False)

        # get auth url
        client_nonce = uuid.uuid1().hex
        auth_url = get_authorization_url(
            client,
            f"{server.server_uri}{PATH_OIDC_CALLBACK}",
            self.role,
            client_nonce,
        )

        if not auth_url:
            raise AuthenticationError("Failed to reterive OIDC authorization URL")

        # create entrypoint, setup context and start server
        entrypoint = f"/{uuid.uuid1()}"
        entrypoint_url = f"{server.server_uri}{entrypoint}"

        server.context.update(
            auth_url=auth_url,
            client_nonce=client_nonce,
            client=client,
            entrypoint=entrypoint,
        )

        server.ready.set()

        # open entrypoint
        logger.info(
            "<!important>"
            "Waiting for response from OpenID connect provider...\n"
            "If browser does not open automatically, open the link:\n"
            f"  <link>{entrypoint_url}</link>"
        )
        webbrowser.open(entrypoint_url)

        # wait until finish
        server.server_thread.join()

        # check result
        token = server.context.get("token")
        if not token:
            raise AuthenticationError("Failed to fetch OIDC client token")

        return token


class OIDCRequestHandler(HTTPRequestHandler):
    def route(self, path: str) -> RouteHandler | None:
        if path == PATH_OIDC_CALLBACK:
            return self.do_oidc_callback
        if path == self.server.context["entrypoint"]:
            return self.do_forward_auth_url

    def do_forward_auth_url(self, params: URLParams):
        """Forwards user to auth URL, which is very loooong."""
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", self.server.context["auth_url"])
        self.send_header("Cache-control", "no-store")
        self.end_headers()

    def do_oidc_callback(self, params: URLParams):
        # get authorization code
        codes = params.get("code")
        if not codes:
            self.response_error(HTTPStatus.BAD_REQUEST)
            return

        code = codes[0]

        # request token
        token = request_token(
            self.server.context["client"],
            self.server.context["auth_url"],
            code,
            self.server.context["client_nonce"],
        )
        if not token:
            self.response_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.server.context["token"] = token
        self.response_html(HTTPStatus.OK, "oidc-success.html")
        self.server.shutdown()


def get_authorization_url(
    client: httpx.Client, redirect_uri: str, role: str | None, client_nonce: str
) -> str | None:
    """Get OIDC authorization URL.

    See also
    --------
    https://developer.hashicorp.com/vault/api-docs/auth/jwt#oidc-authorization-url-request

    Exceptions
    ----------
    AuthenticationError
        On requesting URL failed.
    """
    if redirect_uri.startswith("http://127.0.0.1"):
        # vault only accepts hostname from pre-configured accept list
        # `localhost` is in the list but `127.0.0.1` is not
        redirect_uri = redirect_uri.replace("http://127.0.0.1", "http://localhost", 1)

    payload = {
        "redirect_uri": redirect_uri,
        "client_nonce": client_nonce,
    }
    if role:
        payload["role"] = role

    resp = client.post("/v1/auth/oidc/oidc/auth_url", json=payload)

    if resp.status_code == HTTPStatus.OK:
        # when `redirect_uri` is not accepted, it still response 200 but
        # `auth_url` would be empty string
        data = resp.json()
        return data["data"]["auth_url"]

    logger.error("Error requesting authorization URL")
    logger.debug("Code= %d. Raw response= %s", resp.status_code, resp.text)
    return None


def request_token(
    client: httpx.Client, auth_url: str, auth_code: str, client_nonce: str
) -> str | None:
    """Exchange authorization code for client token.

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

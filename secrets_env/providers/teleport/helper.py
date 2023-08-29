"""An helper module that wraps `Teleport CLI`_ (``tsh``) and get connection
information from it.

.. _Teleport CLI: https://goteleport.com/docs/reference/cli/
"""
import atexit
import dataclasses
import datetime
import importlib.util
import json
import logging
import os
import shutil
import tempfile
import typing
from functools import cached_property
from pathlib import Path
from typing import Dict, Iterable, Optional

from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.subprocess import Run

if typing.TYPE_CHECKING:
    from secrets_env.providers.teleport.config import AppParameter


TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class AppConnectionInfo:
    """Teleport app connection information.

    This object copied the certificate on object creation, and destroy them
    when secrets.env terminated.
    """

    uri: str
    """URI to the app."""

    ca: Optional[bytes]
    """Certificate authority (CA) certificate."""

    cert: bytes
    """Client side certificate."""

    key: bytes
    """Client side private key."""

    @classmethod
    def from_config(cls, uri: str, ca: str, cert: str, key: str) -> "AppConnectionInfo":
        path_ca = Path(ca)
        if path_ca.is_file():  # CA is not always installed
            data_ca = path_ca.read_bytes()
        else:
            data_ca = None

        with open(cert, "rb") as fd:
            data_cert = fd.read()
        with open(key, "rb") as fd:
            data_key = fd.read()

        return cls(uri=uri, ca=data_ca, cert=data_cert, key=data_key)

    @property
    def cert_and_key(self) -> bytes:
        return self.cert + b"\n" + self.key

    @cached_property
    def path_ca(self) -> Optional[Path]:
        if not self.ca:
            return None
        return create_temp_file(".crt", self.ca)

    @cached_property
    def path_cert(self) -> Path:
        return create_temp_file(".cert", self.cert)

    @cached_property
    def path_key(self) -> Path:
        return create_temp_file(".key", self.key)

    @cached_property
    def path_cert_and_key(self) -> Path:
        return create_temp_file(".pem", self.cert_and_key)


def create_temp_file(suffix: str, data: bytes) -> Path:
    fd, path = tempfile.mkstemp(suffix=suffix)

    os.write(fd, data)
    os.close(fd)

    atexit.register(os.remove, path)

    return Path(path)


def get_connection_info(params: "AppParameter") -> AppConnectionInfo:
    """Get app connection information from Teleport API.

    Parameters
    ----------
    params : AppParameter
        Parameters parsed by :py:mod:`~secrets_env.providers.teleport.config`.

    Raises
    ------
    AuthenticationError
        Failed to login to Teleport.
    UnsupportedError
        When Teleport CLI not installed.
    """
    # ensure teleport cli is installed
    if not shutil.which(TELEPORT_APP_NAME):
        raise UnsupportedError(
            "Teleport CLI ({}) is required for teleport integration", TELEPORT_APP_NAME
        )

    # it might take a while for teleport RPC. show the message to indicate it
    # is not freeze
    app = params["app"]
    logger.info("<!important>Get connection information from Teleport for %s", app)
    logger.debug("Teleport app parameters= %s", params)

    # log version before start
    if not call_version():
        raise SecretsEnvError("Internal error on accessing Teleport CLI")

    # try to get config directly; when not available, loging and retry
    cfg = attempt_get_app_config(app)

    if not cfg:
        call_app_login(params)
        cfg = call_app_config(app)

    if not cfg:
        raise AuthenticationError("Failed to get connection info from Teleport")

    return AppConnectionInfo.from_config(**cfg)


def attempt_get_app_config(app: str) -> Dict[str, str]:
    """The certificate refreshing process takes a while so we'd like to directly
    use the one stored on disk. Teleport sometimes responds the file path without
    expiration check. Therefore we need to check it by ourself.
    """
    # need cryptography package to read cert file
    if not importlib.util.find_spec("cryptography"):
        return {}

    logger.debug("Try to get config directly")
    config = call_app_config(app)
    if not config:
        # case: not login yet / teleport detect expired
        return {}

    if not is_certificate_valid(config["cert"]):
        # case: detect expired by ourself
        return {}

    return config


def is_certificate_valid(filepath: str) -> bool:
    import cryptography.x509

    with open(filepath, "rb") as fd:
        data = fd.read()

    cert = cryptography.x509.load_pem_x509_certificate(data)
    now = datetime.datetime.utcnow()
    if now > cert.not_valid_after:
        logger.debug(
            "Certificate expire at: %s < current time %s", cert.not_valid_after, now
        )
        return False

    return True


def call_version() -> bool:
    """Call version command and print it to log."""
    runner = run_teleport(["version"])
    return runner.return_code == 0


def call_app_config(app: str) -> Dict[str, str]:
    runner = run_teleport(["app", "config", "--format=json", app])
    if runner.return_code != 0:
        return {}
    return json.loads(runner.stdout)


def call_app_login(params: "AppParameter") -> None:
    """Call `tsh app login`. Only returns on success.

    Raises
    ------
    AuthenticationError
        Login failed
    """
    app = params["app"]

    # build arguments
    cmd = [TELEPORT_APP_NAME, "app", "login"]
    if proxy := params.get("proxy"):
        cmd.append(f"--proxy={proxy}")
    if cluster := params.get("cluster"):
        cmd.append(f"--cluster={cluster}")
    if user := params.get("user"):
        cmd.append(f"--user={user}")
    cmd.append(app)

    # run
    runner = Run(cmd)

    for line in runner.iter_any_output():
        # early escape on detect 'success' message from stdout
        if line.startswith("Logged into app"):
            break

        # capture auth url from stderr
        line = line.lstrip()
        if line.startswith("http://127.0.0.1:"):
            logger.info(
                "<!important>"
                "Waiting for response from Teleport...\n"
                "If browser does not open automatically, open the link:\n"
                f"  <link>{line}</link>"
            )

    runner.wait()

    if runner.return_code == 0:
        logger.info("Successfully logged into app %s", app)
        return None

    if f'app "{app}" not found' in runner.stderr:
        raise AuthenticationError("Teleport app '{}' not found", app)

    raise AuthenticationError("Teleport error: {}", runner.stderr)


def run_teleport(args: Iterable[str]) -> Run:
    """Run teleport command. Returns execution result."""
    run = Run([TELEPORT_APP_NAME, *args])
    run.wait()
    return run

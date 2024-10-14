from __future__ import annotations

import datetime
import logging
import os
import re
import subprocess
import warnings
from functools import cached_property
from pathlib import Path
from typing import cast

from pydantic import BaseModel, FilePath, SecretBytes, field_validator, model_validator

from secrets_env.exceptions import AuthenticationError, UnsupportedError
from secrets_env.realms.subprocess import check_output, write_output

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


class TeleportUserConfig(BaseModel):
    """Parameters for retrieving app certificates from Teleport."""

    proxy: str | None = None
    cluster: str | None = None
    user: str | None = None
    app: str

    @model_validator(mode="before")
    @classmethod
    def _use_shortcut(cls, data):
        if isinstance(data, str):
            return {"app": data}
        return data

    @cached_property
    def connection_param(self) -> TeleportConnectionParameter:
        """Get app connection parameter from Teleport CLI.

        Raises
        ------
        AuthenticationError
            Failed to login to Teleport.
        UnsupportedError
            When dependency not satisfied.
        """
        ensure_dependencies()

        # it might take a while for teleport RPC. show the message to indicate that
        # the script is not freeze
        logger.info(
            f"<!important>Requesting connection information for <data>{self.app}</data> from Teleport"
        )
        logger.debug(f"Teleport app parameters= {self!r}")

        # log version before start
        if not call_version():
            raise RuntimeError("Internal error on accessing Teleport CLI")

        # try to get config directly; when not available, loging and retry
        param = try_get_app_config(self.app)

        if not param:
            call_app_login(self)
            param = call_app_config(self.app)

        if not param:
            raise AuthenticationError("Failed to get connection info from Teleport")

        return param


def ensure_dependencies():
    """Ensure that the required dependencies are installed."""
    import importlib.util
    import shutil

    if not shutil.which(TELEPORT_APP_NAME):
        raise UnsupportedError(
            f"Teleport CLI ({TELEPORT_APP_NAME}) is required for teleport support"
        )

    if (
        False
        or not importlib.util.find_spec("cryptography")
        or not importlib.util.find_spec("pexpect")
    ):
        _warn("Optional dependency for teleport support is missing.")
        _warn("Please reinstall with the extras <mark>teleport</mark>:")
        _warn("  pipx inject secrets.env 'secrets.env[teleport]'")
        raise UnsupportedError("Missing optional dependencies for teleport support")


def _warn(s: str):
    warnings.warn(s, UserWarning, stacklevel=1)


class TeleportConnectionParameter(BaseModel):
    """App URI and the short-lived certificate for Teleport.

    This object copied the certificate on object creation, and destroy them
    when secrets.env terminated.
    """

    uri: str
    """URI to the app."""

    ca: SecretBytes | None
    """Certificate authority (CA) certificate."""

    cert: SecretBytes
    """Client side certificate."""

    key: SecretBytes
    """Client side private key."""

    @model_validator(mode="before")
    @classmethod
    def _from_tsh_app_config(cls, values):
        if isinstance(values, TshAppConfigResponse):
            return values.model_dump()
        return values

    @field_validator("ca", "cert", "key", mode="before")
    @classmethod
    def _read_bytes_from_path(cls, value: Path | None) -> bytes | None:
        if isinstance(value, Path):
            return value.read_bytes()
        return value

    @staticmethod
    def _create_temp_file(suffix: str, data: bytes) -> Path:
        import atexit
        import tempfile

        fd, path = tempfile.mkstemp(suffix=suffix)

        os.write(fd, data)
        os.close(fd)

        atexit.register(os.remove, path)

        return Path(path)

    @cached_property
    def cert_and_key(self) -> bytes:
        return self.cert.get_secret_value() + b"\n" + self.key.get_secret_value()

    @cached_property
    def path_ca(self) -> Path | None:
        if not self.ca:
            return None
        return self._create_temp_file(".crt", self.ca.get_secret_value())

    @cached_property
    def path_cert(self) -> Path:
        return self._create_temp_file(".cert", self.cert.get_secret_value())

    @cached_property
    def path_key(self) -> Path:
        return self._create_temp_file(".key", self.key.get_secret_value())

    @cached_property
    def path_cert_and_key(self) -> Path:
        return self._create_temp_file(".pem", self.cert_and_key)

    def is_cert_valid(self) -> bool:
        """Check if the certificate is still valid now.

        Raises
        ------
        ImportError
            When `cryptography` package is not installed.
        """
        import cryptography.x509

        cert = cryptography.x509.load_pem_x509_certificate(self.cert.get_secret_value())
        now = datetime.datetime.now().astimezone()
        if now > cert.not_valid_after_utc:
            logger.debug(
                "Certificate expire at %s < current time %s",
                cert.not_valid_after_utc.astimezone(),
                now,
            )
            return False

        return True


def try_get_app_config(app: str) -> TeleportConnectionParameter | None:
    """The certificate refreshing process takes a while so we'd like to directly
    use the one stored on disk. Teleport sometimes responds the file path without
    expiration check. Therefore we need to check it by ourself.
    """
    logger.debug("Try to get config directly")
    param = call_app_config(app, False)
    if not param:
        # not login yet / teleport detect expired
        return

    if not param.is_cert_valid():
        # cert is expired
        return

    return param


def call_version() -> bool:
    """Call version command and print it to log."""
    try:
        check_output([TELEPORT_APP_NAME, "version"])
    except subprocess.CalledProcessError:
        return False
    return True


class TshAppConfigResponse(BaseModel):
    """Layout returned by `tsh app config` command."""

    uri: str
    """URI to the app."""

    ca: Path | None
    """Certificate authority (CA) certificate."""

    cert: FilePath
    """Client side certificate."""

    key: FilePath
    """Client side private key."""

    @field_validator("ca", mode="after")
    @classmethod
    def _drop_on_not_exist(cls, path: Path | None) -> Path | None:
        if isinstance(path, Path):
            if not path.is_file():
                return None
        return path


def call_app_config(
    app: str, report_error: bool = True
) -> TeleportConnectionParameter | None:
    # lowlight error message when `report_error` is False
    level_error = logging.ERROR
    if not report_error:
        level_error = logging.DEBUG

    # get app config
    try:
        stdout = check_output(
            [
                TELEPORT_APP_NAME,
                "app",
                "config",
                "--format=json",
                app,
            ],
            level_error=level_error,
        )
    except subprocess.CalledProcessError:
        return

    config = TshAppConfigResponse.model_validate_json(stdout)
    return TeleportConnectionParameter.model_validate(config)


def call_app_login(config: TeleportUserConfig) -> None:
    """Call `tsh app login`. Only returns on success.

    Raises
    ------
    AuthenticationError
        Login failed
    """
    import io

    import pexpect

    # build arguments
    args = ["app", "login"]
    if config.proxy:
        args.append(f"--proxy={config.proxy}")
    if config.cluster:
        args.append(f"--cluster={config.cluster}")
    if config.user:
        args.append(f"--user={config.user}")
    args.append(config.app)

    logger.debug("$ %s %s", TELEPORT_APP_NAME, " ".join(args))

    # run
    with io.StringIO() as capture_stdout, io.StringIO() as capture_stderr:
        proc = pexpect.spawn(TELEPORT_APP_NAME, args, timeout=None, encoding="utf-8")
        proc.logfile = capture_stdout
        proc.stderr = capture_stderr

        while True:
            index = proc.expect(
                [
                    re.escape(f"Logged into app {config.app}"),
                    r"http://127\.0\.0\.1:\d+/[0-9a-f-]+",
                    re.escape(f'app "{config.app}" not found'),
                    pexpect.EOF,
                ]
            )

            if index == 1:
                match = cast(re.Match, proc.match)
                link = match.group(0)
                logger.info(
                    "<!important>"
                    "Waiting for response from Teleport...\n"
                    "If browser does not open automatically, open the link:\n"
                    f"  <link>{link}</link>"
                )

            elif index == 2:
                raise AuthenticationError(f"Teleport app '{config.app}' not found")

            else:
                break

        proc.close()

        logger.debug("< return code: %s", proc.exitstatus)
        write_output("stdout", capture_stdout.getvalue())
        write_output("stderr", capture_stderr.getvalue())

        if proc.exitstatus != 0:
            write_output("stdout", capture_stdout.getvalue(), logging.ERROR)
            write_output("stderr", capture_stderr.getvalue(), logging.ERROR)
            raise AuthenticationError("Teleport error")

    logger.info(f"Successfully logged into teleport app: {config.app}")

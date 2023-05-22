"""An helper module that wraps `Teleport CLI`_ (``tsh``) and get connection
information from it.

.. _Teleport CLI: https://goteleport.com/docs/reference/cli/
"""
import dataclasses
import json
import logging
import queue
import shutil
import subprocess
import sys
import threading
import time
import typing
from pathlib import Path
from typing import IO, Dict, Iterable, Iterator, List, Optional, Tuple

from secrets_env.exceptions import (
    AuthenticationError,
    SecretsEnvError,
    UnsupportedError,
)
from secrets_env.utils import strip_ansi

if typing.TYPE_CHECKING:
    from secrets_env.providers.teleport.config import AppParameter

    if sys.version_info >= (3, 9):
        StrQueue = queue.Queue[str]
        StrPopen = subprocess.Popen[str]
    else:
        StrQueue = typing.TypeVar("StrQueue", bound=queue.Queue)
        StrPopen = typing.TypeVar("StrPopen", bound=subprocess.Popen)

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class AppConnectionInfo:
    """Teleport app connection information."""

    uri: str
    path_ca: Optional[Path]
    path_cert: Path
    path_key: Path


def get_connection_info(params: "AppParameter") -> AppConnectionInfo:
    """Get app connection information from Teleport API.

    Parameters
    ----------
    app : str
        Teleport application name

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
    logger.debug("Try to get config directly")
    cfg = call_app_config(app)

    if not cfg:
        call_app_login(params)
        cfg = call_app_config(app)

    if not cfg:
        raise AuthenticationError("Failed to get connection info from Teleport")

    # CA is not always installed
    path_ca = None
    if ca := cfg.get("ca"):
        path_ca = Path(ca)
        if not path_ca.exists():
            path_ca = None

    cert_path = Path(cfg["cert"])
    path_key = Path(cfg["key"])

    return AppConnectionInfo(
        uri=cfg["uri"],
        path_ca=path_ca,
        path_cert=cert_path,
        path_key=path_key,
    )


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
    if user := params.get("user"):
        cmd.append(f"--user={user}")
    cmd.append(app)

    # run
    runner = _RunCommand(cmd)

    auth_url_captured = False
    for line in runner:
        # early escape on detect 'success' message from stdout
        if line.startswith("Logged into app"):
            break

        # capture auth url from stdout
        if not auth_url_captured and line.lstrip().startswith("http://127.0.0.1:"):
            auth_url_captured = True
            logger.info(
                "<!important>"
                "Waiting for response from Teleport...\n"
                "If browser does not open automatically, open the link:\n"
                f"  <link>{line}</link>"
            )

    if runner.return_code == 0:
        logger.info("Successfully logged into app %s", app)
        return None

    if f'app "{app}" not found' in runner.stderr:
        raise AuthenticationError("Teleport app '{}' not found", app)

    raise AuthenticationError("Teleport error: {}", runner.stderr)


class _RunCommand(threading.Thread):
    """An :py:class:`subprocess.Popen` wrapper that yields stdout in realtime."""

    def __init__(self, cmd: Iterable[str]) -> None:
        super().__init__(daemon=True)
        self._command = tuple(cmd)

        self._return_code = None
        self._stdout_queue: "StrQueue" = queue.Queue()
        self._stdouts: List[str] = []
        self._stderr_queue: "StrQueue" = queue.Queue()
        self._stderrs: List[str] = []

    @property
    def command(self) -> Tuple[str, ...]:
        return self._command

    @property
    def is_completed(self) -> bool:
        return self.ident is not None and not self.is_alive()

    def run(self) -> None:
        """Runs subprocess in background thread in case the iter is early escaped."""
        logger.debug("$ %s", " ".join(self.command))

        # flush output to queue and log it
        def _flush_output_to_queue(stream: IO[str], q: "StrQueue", prefix="<"):
            for line in iter(stream.readline, ""):
                line = strip_ansi(line)
                q.put(line)
                logger.debug("%s %s", prefix, line.rstrip())

        def _flush(proc: "StrPopen"):
            stdout = typing.cast(IO[str], proc.stdout)
            stderr = typing.cast(IO[str], proc.stderr)
            _flush_output_to_queue(stdout, self._stdout_queue)
            _flush_output_to_queue(stderr, self._stderr_queue, "<[stderr]")

        # run command
        with subprocess.Popen(
            args=self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        ) as proc:
            # realtime read outputs to queue
            while proc.poll() is None:
                _flush(proc)

            # get exit code and remaning outputs
            _flush(proc)
            self._return_code = proc.returncode

    def __iter__(self) -> Iterator[str]:
        """Yields stdouts"""
        QUERY_INTERVAL = 0.1

        if self.ident is None:  # not started
            self.start()

        while True:
            try:
                line = self._stdout_queue.get_nowait()
                self._stdouts.append(line)
                yield line.rstrip()
            except queue.Empty:
                if not self.is_alive():
                    break
                time.sleep(QUERY_INTERVAL)

    @property
    def return_code(self) -> int:
        assert self.is_completed
        return self._return_code  # type: ignore[reportOptionalMemberAccess]

    def _build_output(self, queue_: "StrQueue", store: List[str]) -> str:
        while not queue_.empty():
            store.append(queue_.get())
        return "".join(store)

    @property
    def stdout(self) -> str:
        assert self.is_completed
        return self._build_output(self._stdout_queue, self._stdouts)

    @property
    def stderr(self) -> str:
        assert self.is_completed
        return self._build_output(self._stderr_queue, self._stderrs)


def run_teleport(args: Iterable[str]) -> _RunCommand:
    """Run teleport command. Returns execution result."""
    cmd = [TELEPORT_APP_NAME, *args]
    run = _RunCommand(cmd)
    run.start()
    run.join()
    return run

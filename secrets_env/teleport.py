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
import threading
import time
from pathlib import Path
from typing import IO, Dict, Iterable, Iterator, List, Optional, Tuple, TypedDict

from secrets_env.exceptions import AuthenticationError, DependencyError, InternalError

TELEPORT_APP_NAME = "tsh"

logger = logging.getLogger(__name__)


def _command(*args: Iterable[str]) -> List[str]:
    """Build command and log it"""
    cmd = [TELEPORT_APP_NAME, *args]
    logger.debug("$ %s", " ".join(cmd))
    return cmd


def call_version() -> bool:
    """Call version command and print it to log."""
    res = subprocess.run(
        _command("version"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
    )
    if res.returncode != 0:
        return False
    for line in res.stdout.splitlines():
        logger.debug("< %s", line)
    return True


def call_app_config(app: str) -> Dict[str, str]:
    res = subprocess.run(
        _command("app", "config", "--format=json", app),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if res.returncode != 0:
        return {}
    return json.loads(res.stdout)


class _RunCommand(threading.Thread):
    """An :py:class:`subprocess.Popen` wrapper that yields stdout in realtime."""

    def __init__(self, cmd: Iterable[str]) -> None:
        super().__init__(daemon=True)
        self._command = tuple(cmd)

        self._complete = threading.Event()
        self._return_code = None
        self._stdout_queue: queue.Queue[str] = queue.Queue()
        self._stdouts: List[str] = []
        self._stderr_queue: queue.Queue[str] = queue.Queue()
        self._stderrs: List[str] = []

    @property
    def command(self) -> Tuple[str, ...]:
        return self._command

    def run(self) -> None:
        """Runs subprocess in background thread in case the iter is early escaped."""
        logger.debug("$ %s", " ".join(self.command))

        # flush output to queue and log it
        def _flush(stream: IO[str], store: queue.Queue[str], prefix="<"):
            for line in iter(stream.readline, ""):
                store.put(line)
                logger.debug("%s %s", prefix, line.rstrip())

        # run command
        with subprocess.Popen(
            args=self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        ) as proc:
            # let type checker believe stdout & stderr is not none
            assert proc.stdout
            assert proc.stderr

            # realtime read outputs to queue
            while proc.poll() is None:
                _flush(proc.stdout, self._stdout_queue)
                _flush(proc.stderr, self._stderr_queue, "<[stderr]")

            # get exit code and remaning outputs
            self._return_code = proc.returncode
            _flush(proc.stdout, self._stdout_queue)
            _flush(proc.stderr, self._stderr_queue, "<[stderr]")

        self._complete.set()

    def __iter__(self) -> Iterator[str]:
        """Yields stdouts"""
        QUERY_INTERVAL = 0.1
        while True:
            try:
                line = self._stdout_queue.get_nowait()
                self._stdouts.append(line)
                yield line.rstrip()
            except queue.Empty:
                if self._complete.is_set():
                    break
                time.sleep(QUERY_INTERVAL)

    @property
    def return_code(self) -> int:
        assert self._complete.is_set()
        return self._return_code  # type: ignore[reportOptionalMemberAccess]

    def _build_output(self, queue_: queue.Queue[str], store: List[str]) -> str:
        assert self._complete.is_set()
        while not queue_.empty():
            store.append(queue_.get())
        return "".join(store)

    @property
    def stdout(self) -> str:
        return self._build_output(self._stdout_queue, self._stdouts)

    @property
    def stderr(self) -> str:
        return self._build_output(self._stderr_queue, self._stderrs)

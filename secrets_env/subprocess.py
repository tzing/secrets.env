import enum
import logging
import queue
import subprocess
import threading
import time
from typing import IO, Iterator, List, Optional, Sequence, Tuple

from secrets_env.utils import strip_ansi

logger = logging.getLogger(__name__)


class Channel(enum.IntEnum):
    prefix: str

    def __new__(cls, value: int, prefix: str) -> "Channel":
        obj = int.__new__(cls, value)
        obj._value_ = value
        obj.prefix = prefix
        return obj

    Stdout = 1, "<"
    Stderr = 2, "<[stderr]"


class Run:
    """Yet another :py:class:`subprocess.Popen` wrapper. Runs subprocess and
    yields both stdout and stderr in real time."""

    def __init__(self, cmd: Sequence[str]) -> None:
        """Starts a run."""
        self._queue = queue.Queue()
        self._stdouts: List[str] = []
        self._stderrs: List[str] = []

        # start process
        logger.debug("$ %s", " ".join(cmd))

        self._proc = subprocess.Popen(
            args=cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            encoding="utf-8",
        )

        # fire threads to read output
        self._threads = (
            threading.Thread(
                target=polling_output,
                args=(Channel.Stdout, self._proc.stdout, self._queue),
                daemon=True,
            ),
            threading.Thread(
                target=polling_output,
                args=(Channel.Stderr, self._proc.stderr, self._queue),
                daemon=True,
            ),
        )

        for t in self._threads:
            t.start()

    def _iter_output(self) -> Iterator[Tuple[Channel, str]]:
        POLL_INTERVAL = 0.05

        def _flush_queue():
            while not self._queue.empty():
                ch, line = self._queue.get_nowait()
                if ch == Channel.Stdout:
                    self._stdouts.append(line)
                else:
                    self._stderrs.append(line)
                yield ch, line

        while self._proc.poll() is None:
            yield from _flush_queue()
            time.sleep(POLL_INTERVAL)

        time.sleep(POLL_INTERVAL)
        yield from _flush_queue()

    def wait(self) -> int:
        """Wait until process terminated"""
        for _ in self._iter_output():
            ...
        return self._proc.wait()

    def iter_any_output(self) -> Iterator[str]:
        """Reads any output in real time.

        This method does not impacts :py:attr:`stdout` or :py:attr:`stderr`."""
        for _, line in self._iter_output():
            yield line

    @property
    def return_code(self) -> Optional[int]:
        """The child process return code"""
        return self._proc.returncode

    @property
    def stdout(self) -> str:
        """Wait until process terminated and returns stdout outputs"""
        self.wait()
        return "".join(self._stdouts)

    @property
    def stderr(self) -> str:
        """Wait until process terminated and returns stderr outputs"""
        self.wait()
        return "".join(self._stderrs)


def polling_output(ch: Channel, source: IO[str], q: queue.Queue):
    for line in source:
        q.put((ch, line))
        logger.debug("%s %s", ch.prefix, strip_ansi(line.rstrip()))

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
    """Run subprocess and yields both stdout and stderr in real time."""

    def __init__(self, cmd: Sequence[str]) -> None:
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
        POLL_INTERVAL = 0.1
        while True:
            try:
                ch, line = self._queue.get_nowait()
                if ch == Channel.Stdout:
                    self._stdouts.append(line)
                else:
                    self._stderrs.append(line)
                yield ch, line

            except queue.Empty:
                if self._proc.poll() is not None:
                    break
                time.sleep(POLL_INTERVAL)

    def wait(self) -> int:
        """Wait until process terminated"""
        for t in self._threads:
            t.join()
        return self._proc.wait()

    def _flush(self):
        self.wait()
        for _ in self._iter_output():
            ...

    def iter_any_output(self) -> Iterator[str]:
        """Reads any output. This method does not impacts :py:attr:`stdout` or
        :py:attr:`stderr`."""
        for _, line in self._iter_output():
            yield line

    @property
    def return_code(self) -> Optional[int]:
        """The child return code"""
        return self._proc.returncode

    @property
    def stdout(self) -> str:
        """Returns stdout outputs"""
        self._flush()
        return "".join(self._stdouts)

    @property
    def stderr(self) -> str:
        """Returns stderr outputs"""
        self._flush()
        return "".join(self._stderrs)


def polling_output(ch: Channel, source: IO[str], q: queue.Queue):
    for line in source:
        q.put((ch, line))
        logger.debug("%s %s", ch.prefix, strip_ansi(line.rstrip()))

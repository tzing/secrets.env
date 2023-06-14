import enum
import logging
import queue
import subprocess
import threading
from typing import IO, List, Sequence

logger = logging.getLogger(__name__)


class Channel(enum.Enum):
    Stdout = enum.auto()
    Stderr = enum.auto()


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
        threading.Thread(
            target=polling_output,
            args=(Channel.Stdout, self._proc.stdout, self._queue),
            daemon=True,
        ).start()

        threading.Thread(
            target=polling_output,
            args=(Channel.Stderr, self._proc.stderr, self._queue),
            daemon=True,
        ).start()


def polling_output(ch: Channel, source: IO[str], q: queue.Queue):
    logger.debug(
        "Subprocess polling worker created. thread id= %s; channel = %s",
        threading.get_native_id(),
        ch.name,
    )

    for line in source:
        q.put((ch, line))

    logger.debug(
        "Subprocess polling worker shutdown. thread id= %s; channel = %s",
        threading.get_native_id(),
        ch.name,
    )

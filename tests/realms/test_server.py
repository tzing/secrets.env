import http.server
import logging
import re
import time

import httpx
import pytest

from secrets_env.realms.server import ThreadSafeDict, get_free_port, start_server


class TestThreadedHttpServer:
    def test(self, caplog: pytest.LogCaptureFixture):
        # test lifecycle
        with caplog.at_level(logging.DEBUG):
            server = start_server(
                http.server.SimpleHTTPRequestHandler, auto_ready=False
            )
            time.sleep(0.1)
        assert len(caplog.records) == 1
        assert "HTTP server thread created." in caplog.text

        with caplog.at_level(logging.DEBUG):
            server.ready.set()
            time.sleep(0.1)
        assert len(caplog.records) == 2
        assert "Start listening ('127.0.0.1'," in caplog.text

        with caplog.at_level(logging.DEBUG):
            server.shutdown()
            time.sleep(0.1)
        assert len(caplog.records) == 3
        assert "HTTP Server shutdown" in caplog.text

        # test server_url
        assert re.match(r"http://127\.0\.0\.1:\d+", server.server_url)


class TestThreadSafeDict:
    def test(self):
        d = ThreadSafeDict()
        d["foo"] = "bar"
        d.setdefault("bar", "baz")
        assert len(d) == 2
        assert repr(d) == "{'foo': 'bar', 'bar': 'baz'}"

        assert d.pop("bar") == "baz"
        assert "bar" not in d
        assert list(d) == ["foo"]


def test_get_free_port():
    port = get_free_port()
    assert isinstance(port, int)
    assert 1023 < port < 65536

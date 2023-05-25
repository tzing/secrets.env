import logging
import time
from http import HTTPStatus

import httpx
import pytest

import secrets_env.server as t


def test_safe_dict():
    d = t.SafeDict()
    d["foo"] = "bar"
    d.setdefault("bar", "baz")
    assert len(d) == 2
    assert repr(d) == "{'foo': 'bar', 'bar': 'baz'}"

    assert d.pop("bar") == "baz"
    assert "bar" not in d
    assert list(d) == ["foo"]


def test_server_control(caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.DEBUG, "secrets_env.server"):
        # create server
        server = t.start_server(t.HTTPRequestHandler, ready=False)

        time.sleep(0.1)
        assert len(caplog.records) == 1
        assert "HTTP server thread created." in caplog.text

        # ready
        server.ready.set()

        time.sleep(0.1)
        assert len(caplog.records) == 2
        assert "Start listening ('127.0.0.1', " in caplog.text

        # stop
        server.shutdown()

        time.sleep(0.1)
        assert len(caplog.records) == 3
        assert "HTTP Server shutdown" in caplog.text


class TestRequest:
    class Handler(t.HTTPRequestHandler):
        def route(self, path: str):
            if path == "/ok":
                return self.ok

        def ok(self, params: dict):
            self.send_response(HTTPStatus.OK)
            self.end_headers()

    def setup_class(self):
        self.server = t.start_server(self.Handler)

    def teardown_class(self):
        self.server.shutdown()

    @pytest.mark.parametrize(
        ("path", "code"),
        [
            ("/ok", 200),
            ("/not-found", 404),
        ],
    )
    def test(self, path: str, code: int):
        resp = httpx.get(self.server.server_uri + path)
        assert resp.status_code == code


def test_get_free_port():
    port = t.get_free_port()
    assert isinstance(port, int)
    assert 1023 < port < 65536

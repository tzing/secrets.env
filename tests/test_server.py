import logging
import time
from http import HTTPStatus

import httpx
import pytest

import secrets_env.server as t


def test_server_control(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(t.HTTPRequestHandler, "__abstractmethods__", set())

    with caplog.at_level(logging.DEBUG, "secrets_env.server"):
        # create server
        server = t.start_server(t.HTTPRequestHandler, need_prepare=True)

        time.sleep(0.1)
        assert len(caplog.records) == 1
        assert "HTTP server created." in caplog.text

        # ready
        server.ready.set()

        time.sleep(0.1)
        assert len(caplog.records) == 2
        assert "Start listening ('127.0.0.1', " in caplog.text

        # stop
        server.shutdown()

        time.sleep(0.1)
        assert len(caplog.records) == 3
        assert "Stop listen ('127.0.0.1', " in caplog.text


class TestRequest:
    class Handler(t.HTTPRequestHandler):
        def route(self, path: str):
            if path == "/ok":
                return self.ok

        def ok(self, params: dict):
            self.send_response(HTTPStatus.OK)
            self.end_headers()

    @pytest.fixture(scope="class", autouse=True)
    def _run_server(self):
        server = t.start_server(self.Handler, port=56789)
        yield
        server.shutdown()

    @pytest.mark.parametrize(
        ("path", "code"),
        [
            ("ok", 200),
            ("not-found", 404),
        ],
    )
    def test(self, path: str, code: int):
        resp = httpx.get(f"http://localhost:56789/{path}")
        assert resp.status_code == code


def test_get_free_port():
    port = t.get_free_port()
    assert isinstance(port, int)
    assert 1023 < port < 65536

import io
import logging
import pathlib
import time
from http import HTTPStatus
from unittest.mock import Mock

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


def test_template(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path):
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "example.txt").write_text("hello world!")

    handler = Mock(spec=t.HTTPRequestHandler)
    handler.wfile = io.BytesIO()

    with monkeypatch.context() as ctx:
        ctx.setattr("pathlib.Path", lambda _: tmp_path / "server.py")
        t.HTTPRequestHandler.write_template(handler, "example.txt")

    handler.wfile.seek(io.SEEK_SET)
    assert handler.wfile.read() == b"hello world!"


def test_server_control(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(t.HTTPRequestHandler, "__abstractmethods__", set())

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

import threading

import secrets_env.auth.oidc as t
import requests

from http import HTTPStatus


def test_callback_service():
    auth = t.OpenIDConnectAuth("test")

    thread = auth.start_server(56789)
    assert isinstance(thread, threading.Thread)

    # invalid calls - the thread should not stop
    resp = requests.get("http://localhost:56789/invalid-path")
    assert resp.status_code == HTTPStatus.NOT_FOUND

    resp = requests.get("http://localhost:56789/callback?param=invalid")
    assert resp.status_code == HTTPStatus.BAD_REQUEST

    assert thread.is_alive()

    # valid call - the thread should stop
    resp = requests.get("http://localhost:56789/callback?code=test")
    assert resp.status_code == HTTPStatus.OK

    thread.join()
    assert auth.authorization_code == "test"

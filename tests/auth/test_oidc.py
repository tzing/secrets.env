import threading
import time
from http import HTTPStatus

import requests

import secrets_env.auth.oidc as t


def test_callback_service():
    auth = t.OpenIDConnectAuth("test")

    thread = t.OpenIDConnectCallbackService(56789, auth)
    thread.start()
    assert isinstance(thread, threading.Thread)

    # invalid calls - the thread should not stop
    resp = requests.get("http://localhost:56789/invalid-path")
    assert resp.status_code == HTTPStatus.NOT_FOUND

    resp = requests.get("http://localhost:56789/oidc/callback?param=invalid")
    assert resp.status_code == HTTPStatus.BAD_REQUEST

    assert thread.is_alive()

    # valid call - the thread should stop
    resp = requests.get("http://localhost:56789/oidc/callback?code=test")
    assert resp.status_code == HTTPStatus.OK

    thread.join()
    assert auth.authorization_code == "test"


def test_stop_callback_service():
    thread = t.OpenIDConnectCallbackService(56789, None)
    thread.start()
    assert thread.is_alive() is True

    thread.shutdown_server()

    time.sleep(0.2)
    assert thread.is_alive() is False

    thread.shutdown_server()  # should be no error

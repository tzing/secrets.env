from pathlib import Path

import pytest

import secrets_env.config.types as t


class TestEnsureType:
    def test_success(self):
        assert t.ensure_type("test", 1234, "mock", int, True, 0) == (1234, True)
        assert t.ensure_type("test", "1234", "mock", int, True, 0) == (1234, True)

    def test_no_cast(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "1234", "mock", int, False, 0) == (0, False)
        assert (
            "Expect <mark>mock</mark> type for config <mark>test</mark>, "
            "got <data>1234</data> (<mark>str</mark> type)"
        ) in caplog.text

    def test_cast_fail(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "not a number", "mock", int, True, 0) == (0, False)
        assert (
            "Expect <mark>mock</mark> type for config <mark>test</mark>, "
            "got <data>not a number</data> (<mark>str</mark> type)"
        ) in caplog.text


def test_ensure_str():
    assert t.ensure_str("test", "hello") == ("hello", True)
    assert t.ensure_str("test", "") == ("", True)

    assert t.ensure_str("test", 1234) == (None, False)
    assert t.ensure_str("test", {"foo": "bar"}) == (None, False)


def test_ensure_dict():
    assert t.ensure_dict("test", {"foo": "bar"}) == ({"foo": "bar"}, True)
    assert t.ensure_dict("not-dict", "hello") == ({}, False)


def test_ensure_path(caplog: pytest.LogCaptureFixture):
    # pass
    path = Path("/data/file")
    assert t.ensure_path("test", path, False) == (Path("/data/file"), True)

    # casted
    assert t.ensure_path("test", "/data/file", False) == (Path("/data/file"), True)

    # can't cast
    assert t.ensure_path("test", 1234, False) == (None, False)

    # not exist
    assert t.ensure_path("test", "/data/file", True) == (None, False)
    assert (
        "Expect valid path for config <mark>test</mark>: "
        "file <data>/data/file</data> not exists"
    ) in caplog.text


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."

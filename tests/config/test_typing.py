import secrets_env.config.typing as t

import pytest


class TestEnsureType:
    def test_success(self):
        assert t.ensure_type("test", 1234, "int", int, True, 0) == (1234, True)
        assert t.ensure_type("test", "1234", "int", int, True, 0) == (1234, True)

    def test_no_cast(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "1234", "int", int, False, 0) == (0, False)
        assert (
            "Expect <mark>int</mark> type for config <mark>test</mark>, "
            "got <data>1234</data> (<mark>str</mark> type)"
        ) in caplog.text

    def test_cast_fail(self, caplog: pytest.LogCaptureFixture):
        assert t.ensure_type("test", "not a number", "int", int, True, 0) == (0, False)
        assert (
            "Expect <mark>int</mark> type for config <mark>test</mark>, "
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


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."

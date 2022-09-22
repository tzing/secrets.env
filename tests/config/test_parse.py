import pytest

import secrets_env.config.parse as t
from secrets_env.config.types import SecretPath


class TestParsePath:
    def test_str(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_path("test", "foo#bar") == SecretPath("foo", "bar")
        assert t.parse_path("test", "foo#b") == SecretPath("foo", "b")
        assert t.parse_path("test", "f#bar") == SecretPath("f", "bar")

        assert t.parse_path("test-fail-1", "") is None
        assert t.parse_path("test-fail-2", "#") is None
        assert t.parse_path("test-fail-3", "foo#") is None
        assert t.parse_path("test-fail-4", "#bar") is None

        assert (
            "Target secret <data>test-fail-4</data> is invalid. "
            "Failed to parse string '<data>#bar</data>'. Skip this variable."
        ) in caplog.text

    def test_dict(self, caplog: pytest.LogCaptureFixture):
        assert t.parse_path("test", {"path": "foo", "key": "bar"}) == SecretPath(
            "foo", "bar"
        )

        assert t.parse_path("test-fail-1", {"path": "foo"}) is None
        assert t.parse_path("test-fail-2", {"key": "bar"}) is None
        assert t.parse_path("test-fail-3", {"path": "foo", "key": 1234}) is None
        assert t.parse_path("test-fail-4", {"path": 1234, "key": "bar"}) is None

        assert (
            "Target secret <data>test-fail-4</data> is invalid. "
            "Missing required key <mark>path</mark> or <mark>key</mark>. "
            "Skip this variable."
        ) in caplog.text


def test_ensure_type(caplog: pytest.LogCaptureFixture):
    assert t.ensure_type("test", "str", "hello") == ("hello", True)
    assert t.ensure_type("test", "dict", {"foo": "bar"}) == ({"foo": "bar"}, True)

    assert t.ensure_type("not-str", "str", 123) == (None, False)
    assert (
        "Config <data>not-str</data> is malformed: "
        "expect <mark>str</mark> type, "
        "got '<data>123</data>' (<mark>int</mark> type)"
    ) in caplog.text

    assert t.ensure_type("not-dict", "dict", "hello") == ({}, False)
    assert (
        "Config <data>not-dict</data> is malformed: "
        "expect <mark>dict</mark> type, "
        "got '<data>hello</data>' (<mark>str</mark> type)"
    ) in caplog.text


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."

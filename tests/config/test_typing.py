import secrets_env.config.typing as t

import pytest


def test_ensure_type(caplog: pytest.LogCaptureFixture):
    assert t.ensure_type("test.var", 1234, int, "int", 0) == (1234, True)
    assert t.ensure_type("test.var", "1234", int, "int", 0) == (1234, True)

    assert t.ensure_type("test.var", "not a number", int, "int", 0) == (0, False)
    assert (
        "Expect <mark>int</mark> type for config <mark>test.var</mark>, "
        "got <data>not a number</data> (<mark>str</mark> type)"
    ) in caplog.text


def test_trimmed_str():
    assert t.trimmed_str("hello") == "hello"
    assert t.trimmed_str(1234) == "1234"
    assert t.trimmed_str({"foo": "bar"}) == "{'foo': 'bar'}"

    assert t.trimmed_str("a very long long long item") == "a very long long ..."

import pytest

import secrets_env.config.parse as t
from secrets_env.config.types import SecretPath


class TestGetURL:
    def setup_method(self):
        self.data = {"url": "https://data.example.com"}

    def test_data(self):
        assert t.get_url(self.data) == ("https://data.example.com", True)

    @pytest.mark.parametrize("var_name", ["SECRETS_ENV_ADDR", "VAULT_ADDR"])
    def test_env(self, monkeypatch: pytest.MonkeyPatch, var_name: str):
        monkeypatch.setenv(var_name, "https://env.example.com")
        assert t.get_url(self.data) == ("https://env.example.com", True)

    def test_no_data(self, caplog: pytest.LogCaptureFixture):
        assert t.get_url({}) == (None, False)
        assert "Missing required config '<data>url</data>'." in caplog.text

    def test_type_error(self):
        assert t.get_url({"url": object()}) == (None, False)


def test_parse_section_secrets():
    assert t.parse_section_secrets(
        {
            "var1": "foo#bar",  # valid
            "VAR2": "foo#",  # path invalid
            "3var": "foo#bar",  # name invalid
            "VAR4": "foo#bar",  # valid
        }
    ) == {
        "var1": SecretPath("foo", "bar"),
        "VAR4": SecretPath("foo", "bar"),
    }


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


def test_ensure_str(caplog: pytest.LogCaptureFixture):
    assert t.ensure_str("test", "hello") == ("hello", True)

    assert t.ensure_str("not-str", 123) == (None, False)
    assert (
        "Config <data>not-str</data> is malformed: "
        "expect <mark>str</mark> type, "
        "got '<data>123</data>' (<mark>int</mark> type)"
    ) in caplog.text


def test_ensure_dict(caplog: pytest.LogCaptureFixture):
    assert t.ensure_dict("test", {"foo": "bar"}) == ({"foo": "bar"}, True)

    assert t.ensure_dict("not-dict", "hello") == ({}, False)
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

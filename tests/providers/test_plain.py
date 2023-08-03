import secrets_env.providers.plain as t
import pytest


def test():
    provider = t.get_provider("plain", {})
    assert provider.type == "plain"

    assert provider.get("foo") == "foo"
    assert provider.get("") == ""
    assert provider.get({"value": "foo"}) == "foo"
    assert provider.get({"value": None}) == ""

    with pytest.raises(TypeError):
        provider.get(None)

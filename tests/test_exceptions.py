import pytest

import secrets_env.exceptions as t


def test_type_error():
    with pytest.raises(TypeError, match="Expect str for test, got int"):
        raise t.TypeError("test", str, 123)

    with pytest.raises(TypeError, match="Expect str-like for test, got float"):
        raise t.TypeError("test", "str-like", 123.4)

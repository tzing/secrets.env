import pytest

import secrets_env.click


@pytest.fixture(autouse=True)
def _stop_setup_logging(monkeypatch: pytest.MonkeyPatch):
    """the customized logging setup breaks pytest's log capture fixture"""
    monkeypatch.setattr(
        secrets_env.click, "setup_logging", lambda *args, **kwargs: None
    )

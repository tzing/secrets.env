from __future__ import annotations

from pydantic import BaseModel, model_validator


class TeleportUserConfig(BaseModel):
    """Parameters for retrieving app certificates from Teleport."""

    proxy: str | None = None
    cluster: str | None = None
    user: str | None = None
    app: str

    @model_validator(mode="before")
    @classmethod
    def _use_shortcut(cls, data):
        if isinstance(data, str):
            return {"app": data}
        return data

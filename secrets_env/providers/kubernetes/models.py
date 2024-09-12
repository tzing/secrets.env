from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, computed_field, model_validator


class KubeRequest(BaseModel):
    """
    Request to read a secret from Kubernetes.
    """

    ref: str = Field(pattern=r"^[a-z0-9-]+/[a-z0-9-]+$")
    """
    Secret reference in the format ``namespace/secret-name``.
    """

    key: str = Field(pattern=r"^[a-zA-Z0-9-_.]+$")
    """
    Secret key to read.
    """

    @model_validator(mode="before")
    @classmethod
    def _accept_shortcut(cls, data):
        if isinstance(data, dict):
            if data.get("value"):
                path = KubeRequestSimplified.model_validate(data)
                return path.model_dump()
        return data

    @computed_field
    @property
    def namespace(self) -> str:
        namespace, _ = self.ref.split("/", 1)
        return namespace

    @computed_field
    @property
    def name(self) -> str:
        _, name = self.ref.split("/", 1)
        return name


class KubeRequestSimplified(BaseModel):
    """
    Represents a simplified request to read a secret from Kubernetes.
    """

    value: str = Field(pattern=r"^[a-z0-9-]+/[a-z0-9-]+#")

    @computed_field
    def ref(self) -> str:
        ref, _ = self.value.rsplit("#", 1)
        return ref

    @computed_field
    def key(self) -> str:
        _, key = self.value.rsplit("#", 1)
        return key


class KubeSecret(BaseModel):
    apiVersion: Literal["v1"]
    kind: Literal["Secret"]
    data: dict[str, str]

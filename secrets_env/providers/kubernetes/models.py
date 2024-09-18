from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, Field, computed_field, model_validator


class Kind(enum.Enum):
    ConfigMap = enum.auto()
    Secret = enum.auto()

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            value = value.lower()
            if value in ("configmap", "configmaps"):
                return cls.ConfigMap


class KubeRequest(BaseModel):
    """Request to read a value from Kubernetes."""

    ref: str = Field(pattern=r"^[a-z0-9-]+/[a-z0-9.-]+$")
    key: str = Field(pattern=r"^[\w.-]+$")
    kind: Kind = Field(Kind.Secret)

    @model_validator(mode="before")
    @classmethod
    def _accept_shortcut(cls, data):
        if isinstance(data, dict):
            if data.get("value"):
                path = _SimplifiedRequest.model_validate(data)
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


class _SimplifiedRequest(BaseModel):
    """
    Represents a simplified request to read a value from Kubernetes.
    """

    value: str = Field(pattern=r"^[a-z0-9-]+/[a-z0-9.-]+#")

    @computed_field
    @property
    def ref(self) -> str:
        ref, _ = self.value.rsplit("#", 1)
        return ref

    @computed_field
    @property
    def key(self) -> str:
        _, key = self.value.rsplit("#", 1)
        return key


class SecretV1(BaseModel):
    apiVersion: Literal["v1"]
    kind: Literal["Secret"]
    data: dict[str, str]


class ConfigMapV1(BaseModel):
    apiVersion: Literal["v1"]
    kind: Literal["ConfigMap"]
    data: dict[str, str]

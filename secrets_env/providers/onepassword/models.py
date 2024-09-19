from __future__ import annotations

import datetime
import re
from typing import Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, SecretStr


class OpRequest(BaseModel):
    """
    Spec for requesting a value from 1Password.
    """

    ref: str
    field: str

    @property
    def is_uuid(self) -> bool:
        m = re.match(r"^[a-z2-7]{26}$", self.ref)
        return bool(m)


def from_op_ref(ref: str) -> OpRequest:
    u = AnyUrl(ref)
    if not u.scheme == "op":
        raise ValueError(f"Invalid scheme '{u.scheme}'")

    path = u.path or "/"
    parts = path.split("/", maxsplit=2)
    if len(parts) < 3:
        raise ValueError(f"Invalid path '{u.path}'")

    _, ref, field = parts
    return OpRequest(ref=ref, field=field)


class ItemObject(BaseModel):
    """
    Item in the 1Password Vault.

    Ref:
    https://developer.1password.com/docs/connect/connect-api-reference/#item-object
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    category: str
    created_at: datetime.datetime = Field(alias="createdAt")
    fields: list[FieldObject] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    title: str
    updated_at: datetime.datetime = Field(alias="updatedAt")


class FieldObject(BaseModel):
    """
    Field in the 1Password item object.

    Ref:
    https://developer.1password.com/docs/connect/connect-api-reference/#item-field-object
    """

    id: str
    type: str
    purpose: Literal["USERNAME", "PASSWORD", "NOTES"] | None = None
    label: str | None = None
    value: SecretStr | None = None

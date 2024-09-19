from __future__ import annotations

import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class ItemObject(BaseModel):
    """
    Item in the 1Password Vault.

    Ref:
    https://developer.1password.com/docs/connect/connect-api-reference/#item-object
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    title: str
    fields: list[FieldObject]
    created_at: datetime.datetime = Field(alias="createdAt")
    updated_at: datetime.datetime = Field(alias="updatedAt")


class FieldObject(BaseModel):
    """
    Field in the 1Password item object.

    Ref:
    https://developer.1password.com/docs/connect/connect-api-reference/#item-field-object
    """

    id: str
    type: str
    purpose: Literal["USERNAME", "PASSWORD", "NOTES"] | None = Field(None)
    label: str = Field(None)
    value: SecretStr | None = Field(None)

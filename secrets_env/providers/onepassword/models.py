from __future__ import annotations

import datetime  # noqa: TCH003
from typing import Literal

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, SecretStr, model_validator


class OpRequest(BaseModel):
    """
    Spec for requesting a value from 1Password.
    """

    ref: str
    field: str

    @model_validator(mode="before")
    @classmethod
    def _accept_op_ref(cls, values):
        if isinstance(values, dict) and (shortcut := values.get("value")):
            return from_op_ref(shortcut)
        return values


def from_op_ref(ref: str) -> dict:
    u = AnyUrl(ref)
    if not u.scheme == "op":
        raise ValueError(f"Invalid scheme '{u.scheme}'")

    path = u.path or "/"
    parts = path.split("/", maxsplit=2)
    if len(parts) < 3:
        raise ValueError(f"Invalid path '{u.path}'")

    _, ref, field = parts
    return {
        "ref": ref,
        "field": field,
    }


class ItemObject(BaseModel):
    """
    Item in the 1Password Vault.

    Ref:
    https://developer.1password.com/docs/connect/connect-api-reference/#item-object
    """

    # NOTE
    # Response from API and command line tool has different casing.
    # This is a workaround to handle both cases.
    model_config = ConfigDict(populate_by_name=True)

    id: str
    category: str
    created_at: datetime.datetime = Field(alias="createdAt")
    fields: list[FieldObject] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    title: str
    updated_at: datetime.datetime = Field(alias="updatedAt")

    def get_field(self, name: str) -> FieldObject:
        """
        Get a field by ID or name.
        """
        iname = name.lower()

        def match_attr(attr_name: str):
            for field in self.fields:
                attr = getattr(field, attr_name, None)
                if not attr:
                    continue
                if attr.lower() == iname:
                    return field

        if field := match_attr("id"):
            return field
        if field := match_attr("label"):
            return field

        raise KeyError(f'Item {self.title} ({self.id}) has no field "{name}"')


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

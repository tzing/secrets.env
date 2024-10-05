from __future__ import annotations

import datetime  # noqa: TCH003
from typing import Annotated, Literal

from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    UrlConstraints,
    ValidationError,
    model_validator,
    validate_call,
)

SecretReference = Annotated[
    AnyUrl,
    UrlConstraints(allowed_schemes=["op"]),
]


class OpRequest(BaseModel):
    """
    Spec for requesting a value from 1Password.
    """

    ref: str
    field: str

    @model_validator(mode="before")
    @classmethod
    def _accept_secret_ref(cls, values):
        if isinstance(values, dict):
            # shortcut: accept secret reference as a single value
            if shortcut := values.get("value"):
                return parse_secret_reference(shortcut)

            # attempt: accept secret reference in `ref` field
            if ref := values.get("ref"):
                try:
                    return parse_secret_reference(ref)
                except ValidationError:
                    pass

        return values


@validate_call
def parse_secret_reference(u: SecretReference) -> dict[str, str]:
    """
    Parse a secret reference string.

    Ref:
    https://developer.1password.com/docs/cli/secret-reference-syntax/
    """
    path = u.path or "/"
    parts = path.split("/")

    if len(parts) == 3:
        _, item, field = parts
    elif len(parts) == 4:
        _, item, section, field = parts
    else:
        raise ValueError("URL path should be in the format of '/item/section/field'")

    return {
        "ref": item,
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

        raise LookupError(f'Item {self.title} ({self.id}) has no field "{name}"')


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

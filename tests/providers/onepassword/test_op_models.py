import datetime
from typing import cast

import pytest
from pydantic import SecretStr

from secrets_env.providers.onepassword.models import (
    FieldObject,
    ItemObject,
    OpRequest,
    from_op_ref,
)


class TestOpRequest:
    def test(self):
        request = OpRequest.model_validate(
            {"ref": "7h6ve2bxkrs6fu3w25ksebyvpe", "field": "test"}
        )
        assert request.ref == "7h6ve2bxkrs6fu3w25ksebyvpe"
        assert request.field == "test"

    def test_op_ref(self):
        request = OpRequest.model_validate(
            {"value": "op://msocsrixjtzumtrn3wmkgro7vu/Sample/username"}
        )
        assert request.ref == "Sample"
        assert request.field == "username"


class TestFromOpRef:
    def test_success(self):
        data = from_op_ref("op://msocsrixjtzumtrn3wmkgro7vu/Sample/username")
        assert data["ref"] == "Sample"
        assert data["field"] == "username"

    def test_invalid_scheme(self):
        with pytest.raises(ValueError, match="Invalid scheme"):
            from_op_ref("http://example.com/Sample/username")

    def test_invalid_path(self):
        with pytest.raises(ValueError, match="Invalid path"):
            from_op_ref("op://msocsrixjtzumtrn3wmkgro7vu/Sample")


class TestItemObject:

    def test_sample(self):
        SAMPLE_FROM_OFFICIAL_DOC = """
        {
            "id": "2fcbqwe9ndg175zg2dzwftvkpa",
            "title": "Secrets Automation Item",
            "tags": ["connect", "\\ud83d\\udc27"],
            "vault": {"id": "ftz4pm2xxwmwrsd7rjqn7grzfz"},
            "category": "LOGIN",
            "sections": [
                {"id": "95cdbc3b-7742-47ec-9056-44d6af82d562", "label": "Security Questions"}
            ],
            "fields": [
                {
                    "id": "username",
                    "type": "STRING",
                    "purpose": "USERNAME",
                    "label": "username",
                    "value": "wendy"
                },
                {
                    "id": "password",
                    "type": "CONCEALED",
                    "purpose": "PASSWORD",
                    "label": "password",
                    "value": "hLDegPkuMQqyQiyDZqRdWGoojiN5KYQtXuA0wBDe9z3Caj6FQGHpbGu",
                    "entropy": 189.78359985351562
                },
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain"
                },
                {
                    "id": "a6cvmeqakbxoflkgmor4haji7y",
                    "type": "URL",
                    "label": "Example",
                    "value": "https://example.com"
                },
                {
                    "id": "boot3vsxwhuht6g7cmcx4m6rcm",
                    "section": {"id": "95cdbc3b-7742-47ec-9056-44d6af82d562"},
                    "type": "CONCEALED",
                    "label": "Recovery Key",
                    "value": "s=^J@GhHP_isYP>LCq?vv8u7T:*wBP.c"
                },
                {
                    "id": "axwtgyjrvwfp5ij7mtkw2zvijy",
                    "section": {"id": "95cdbc3b-7742-47ec-9056-44d6af82d562"},
                    "type": "STRING",
                    "label": "Random Text",
                    "value": "R)D~KZdV!8?51QoCibDUse7=n@wKR_}]"
                }
            ],
            "files": [
                {
                    "id": "6r65pjq33banznomn7q22sj44e",
                    "name": "testfile.txt",
                    "size": 35,
                    "content_path": "v1/vaults/ftz4pm2xxwmwrsd7rjqn7grzfz/items/2fcbqwe9ndg175zg2dzwftvkpa/files/6r65pjq33banznomn7q22sj44e/content"
                },
                {
                    "id": "oyez5gf6xjfptlhc3o4n6o6hvm",
                    "name": "samplefile.png",
                    "size": 296639,
                    "content_path": "v1/vaults/ftz4pm2xxwmwrsd7rjqn7grzfz/items/2fcbqwe9ndg175zg2dzwftvkpa/files/oyez5gf6xjfptlhc3o4n6o6hvm/content"
                }
            ],
            "createdAt": "2021-04-10T17:20:05.98944527Z",
            "updatedAt": "2021-04-13T17:20:05.989445411Z"
        }
        """

        obj = ItemObject.model_validate_json(SAMPLE_FROM_OFFICIAL_DOC)
        assert obj.id == "2fcbqwe9ndg175zg2dzwftvkpa"
        assert obj.title == "Secrets Automation Item"
        assert len(obj.fields) == 6

        username = obj.fields[0]
        assert username.id == "username"
        assert username.value
        assert username.value.get_secret_value() == "wendy"

    def test_2(self):
        SAMPLE_FROM_CLI = """
        {
            "id": "7h6ve2bxkrs6fu3w25ksebyvpe",
            "title": "Sample",
            "version": 1,
            "vault": {
                "id": "msocsrixjtzumtrn3wmkgro7vu",
                "name": "Test Vault"
            },
            "category": "LOGIN",
            "last_edited_by": "ESQ72MHGV5BKWWZ23HMYMX46IU",
            "created_at": "2022-05-27T05:06:24Z",
            "updated_at": "2023-09-24T13:51:11Z",
            "urls": [
                {
                    "label": "website",
                    "primary": true,
                    "href": "https://example.com/"
                }
            ],
            "fields": [
                {
                    "id": "username",
                    "type": "STRING",
                    "purpose": "USERNAME",
                    "label": "username",
                    "value": "demo",
                    "reference": "op://msocsrixjtzumtrn3wmkgro7vu/Sample/username"
                },
                {
                    "id": "password",
                    "type": "CONCEALED",
                    "purpose": "PASSWORD",
                    "label": "password",
                    "value": "P@ssw0rd",
                    "reference": "op://msocsrixjtzumtrn3wmkgro7vu/Sample/password",
                    "password_details": {
                        "strength": "VERY_GOOD"
                    }
                },
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "reference": "op://msocsrixjtzumtrn3wmkgro7vu/Sample/notesPlain"
                }
            ]
        }
        """

        obj = ItemObject.model_validate_json(SAMPLE_FROM_CLI)
        assert obj.title == "Sample"
        assert len(obj.fields) == 3

        username, password, note = obj.fields
        assert username.id == "username"
        assert username.value
        assert username.value.get_secret_value() == "demo"

        assert password.id == "password"
        assert password.value
        assert password.value.get_secret_value() == "P@ssw0rd"

        assert note.id == "notesPlain"
        assert note.value is None

    @pytest.mark.parametrize(
        ("key", "id_", "value"),
        [
            ("username", "username", "demo"),
            ("bmmzqdwszku6cpq5lwq4pr6v6q", "bmmzqdwszku6cpq5lwq4pr6v6q", "t3st"),
            ("6vl4dok5qanwlmdq7hghbtm3na", "6vl4dok5qanwlmdq7hghbtm3na", "n0te"),
            ("NOTES", "6vl4dok5qanwlmdq7hghbtm3na", "n0te"),
        ],
    )
    def test_get_field(self, key: str, id_: str, value: str):
        now = datetime.datetime.now().astimezone()
        item = ItemObject(
            id="7h6ve2bxkrs6fu3w25ksebyvpe",
            category="LOGIN",
            title="Sample",
            createdAt=now,
            updatedAt=now,
            fields=[
                FieldObject(
                    id="username",
                    type="STRING",
                    purpose="USERNAME",
                    label="username",
                    value=cast(SecretStr, "demo"),
                ),
                FieldObject(
                    id="bmmzqdwszku6cpq5lwq4pr6v6q",
                    type="STRING",
                    value=cast(SecretStr, "t3st"),
                ),
                FieldObject(
                    id="6vl4dok5qanwlmdq7hghbtm3na",
                    type="STRING",
                    label="NOTES",
                    value=cast(SecretStr, "n0te"),
                ),
            ],
        )

        field = item.get_field(key)
        assert field.id == id_
        assert field.value
        assert field.value.get_secret_value() == value

    def test_get_field__key_error(self):
        now = datetime.datetime.now().astimezone()
        item = ItemObject(
            id="7h6ve2bxkrs6fu3w25ksebyvpe",
            category="LOGIN",
            title="Sample",
            createdAt=now,
            updatedAt=now,
        )

        with pytest.raises(KeyError):
            item.get_field("not-exist")

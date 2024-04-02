# Changelogs

*Table of Contents*

<!-- no toc -->
- [Unreleased](#unreleased)
- [Prior to 0.29](#prior-to-029)


## Unreleased

### 🚨 Breaking changes

* Vault userpass auth adapter got renamed from `basic` to `userpass`.

  This change is to align the naming with the Vault's auth method.

* Vault token auth adapter no longer reads token from keyring.

  Vault only provide short-lived tokens, so it is not practical to store them in keyring.

### ✨ Enhancements

* The secrets section in the config file now supports list as well as dictionary.

  ```yaml
  secrets:
    - name: secret1
      source: vault
      path: secret/sample
      field: token
    - name: secret2
      source: plaintext
      value: example
  ```

* Command `keyring set` now accepts password from stdin

### 🚧 Internal changes

* Revise the documentation to ensure consistency across different providers.
* Refactor the configuration parser. Internally switch from using `dict` to [Pydantic](https://docs.pydantic.dev/latest/) models.


## Prior to 0.29

Changes made prior to version 0.29 of secrets.env are not documented.

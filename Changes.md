# Changelogs

*Table of Contents*

- [Unreleased](#unreleased)
  - [✨ Enhancements](#-enhancements)
  - [🚧 Internal changes](#-internal-changes)
- [0.29.1 (2024-05-15)](#0291-2024-05-15)
  - [✨ Enhancements](#-enhancements-1)
- [0.29.0 (2024-05-07)](#0290-2024-05-07)
  - [🚨 Breaking changes](#-breaking-changes)
  - [✨ Enhancements](#-enhancements-2)
  - [🚧 Internal changes](#-internal-changes-1)
- [Prior to 0.29](#prior-to-029)


## Unreleased

### ✨ Enhancements

* Introduce `show` command to parses and displays the configuration file's contents without executing any commands.

  This command helps users understand how secrets.env interprets the configuration file and identifies critical errors.

* Set environment variable `SECRETS_ENV_ACTIVE` and use it to prevent recursive execution of secrets.env.

* Add command `shell` that spawns a shell with the environment variables loaded by secrets.env.

  Users can interact with the shell and use the environment variables.

### 🚧 Internal changes

* Use shellingham to detect the shell type.
* Refactor `console` module.

## 0.29.1 (2024-05-15)

### ✨ Enhancements

* Vault provider now integrates with Vault's [token helper]

  [token helper]: https://www.vaultproject.io/docs/commands/token-helper

* Shifted some alerts to the [warnings] module to minimize the warning notifications displayed to the user.

  [warnings]: https://docs.python.org/3/library/warnings.html


## 0.29.0 (2024-05-07)

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

* Deprecate the `teleport+vault` keyword

  This keyword was used to configure the Teleport-integrated Vault secret provider.
  It is now covered by `vault`.

* Command `keyring set` now accepts password from stdin

### 🚧 Internal changes

* Revise the documentation to ensure consistency across different providers.
* Refactor the configuration parser. Internally switch from using `dict` to [Pydantic](https://docs.pydantic.dev/latest/) models.
* Refactor layout of the adapter classes to make the code more extensible.

## Prior to 0.29

Changes made prior to version 0.29 of secrets.env are not documented.

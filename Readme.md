> **This is an incomplete project.** Code is pushed to Github as a backup.

# vault2env 🔓

Put the secrets from [Vault] to the environment variable.

[Vault]: https://www.vaultproject.io/

<!-- TODO Install -->

## Usage

This project is still under development. It currently don't have an entrypoint.

## Configure

### Configuration file

This app searches for the file that matches following names in the current working directory and parent folders, and load the config from it. When there are more than one exists, the first one would be selected according to the order here:

1. `.vault2env.toml`[^1]
2. `.vault2env.yaml`[^2]
3. `.vault2env.yml`[^2]
4. `.vault2env.json`
5. `pyproject.toml`[^1]

[^1]: TOML format is only supportted when either [tomllib](https://docs.python.org/3.11/library/tomllib.html) or [tomli](https://pypi.org/project/tomli/) is installed.
[^2]: YAML format is only supportted when [PyYAML](https://pypi.org/project/PyYAML/) is installed.

An example config in YAML format:

```yaml
# `core` configured the connection info to the vault.
# This is an *optional* section- though the values under section are required,
# you could provide them using environment variable.
core:
  # Address to vault
  # Could be replaced using `VAULT_ADDR` environment variable
  url: https://example.com/

  # Authentication info
  # Schema for authentication could be complex, read section below.
  auth:
    method: okta
    username: user@example.com

# `secrets` lists the environment variable name, and the path the get the secret value
secrets:
  # The key (VAR1) is the environment variable name to install the secret
  VAR1:
    # Path to read secret from vault
    path: kv/default

    # Path to identify which value to extract, as we may have multiple values in
    # single secret in KV engine.
    # For nested structure, join the keys with dots.
    key: example.to.value

  # Syntax sugar: path#key
  VAR2: "kv/default#example.to.value"
```

> For most supportted file format, they shared the same schema to this example. The only different is [`pyproject.toml`](./tests/fixtures/example-pyproject.toml) format- each section must placed under `tool.vault2env` section, for aligning the community practice.
> Visit [test fixtrue folder](./tests/fixtures/) to read the equivalent expression in each format.

### Authentication

Vault enforce authentication during requests, so we must provide the identity in order to get the secrets.

#### Method

Vault2env adapts several auth methods. You must specify the auth method by either config file or the environment variable `VAULT_METHOD`. Here's the format in config file:

```yaml
---
# standard layout
# arguments could be included in `auth:`
core:
  auth:
    method: okta
    username: user@example.com

---
# alternative layout
# arguments must be avaliable in other source
core:
  auth: token
```

#### Arguments

Arguments could be provided by various source: config file, environment variable and system keyring service.

We're using [keyring] package, which reads and saves the values from OSX [Keychain], KDE [KWallet], etc. For reading/saving value into keyring, use its [command line utility] with the system name `python-vault2env`:

[keyring]: https://keyring.readthedocs.io/en/latest/
[Keychain]: https://en.wikipedia.org/wiki/Keychain_%28software%29
[KWallet]: https://en.wikipedia.org/wiki/KWallet
[command line utility]: https://keyring.readthedocs.io/en/latest/#command-line-utility

```bash
keyring get python-vault2env token/:token
keyring set python-vault2env okta/test@example.com
```

#### Supportted methods

Here's required argument(s), their accepted source, and corresponding keys:

##### `token`

| key   | config file | env var        | keyring        |
|-------|:-----------:|:---------------|:--------------:|
| token |             | `VAULT_TOKEN`  | `token/:token` |

##### `okta`

| key      | config file | env var          | keyring               |
|----------|:-----------:|:-----------------|:----------------------|
| username | `username`  | `VAULT_USERNAME` | `okta/:username`      |
| password |             | `VAULT_PASSWORD` | `okta/YOUR_USER_NAME` |

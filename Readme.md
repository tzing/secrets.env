# vault2env 🔓

Put secrets from [Vault](https://www.vaultproject.io/) to environment variables.

Security is important, but don't want it to be a stumbling block. We love vault, but the practice of getting secrets for local development could be dangerous. Some of us build them into a `.env` file and source it, which brings the risk of credential leaking.

This tool is built to *plug in* secrets into development without landing data on disk. Furthermore, we can safely commit the config file into CVS, for easily reproducing the environment, and reduce the risk of uploading the secrets to the server.


## Usage

> **Note**
>
> Standard CLI usage is not implemented yet.
> Currently this app could only be used as a poetry plugin. And plugin is a poetry **1.2.0** feature, which is still in beta testing.

Get it from this repository:

```bash
# add as poetry global plugin
poetry self add 'git+https://github.com/tzing/vault2env.git@trunk' -E toml

# add to project venv
poetry add --dev 'git+https://github.com/tzing/vault2env.git@trunk' -E toml
```

Folowing extras avaliable:

* `yaml`: supporting YAML config
* `toml`: supporting TOML config, includes using `pyproject.toml`

If none of them are selected, this app only supports the config in JSON format.

### With poetry

You can use this package as a [poetry plugin](https://python-poetry.org/docs/master/plugins/), then this app will pull the secrets from vault on poetry command `run` and `shell`.

```bash
# 1. install plugin
poetry self add 'git+https://github.com/tzing/vault2env.git@trunk' -E yaml

# 2. setup config
#    read configuration section below for details
export VAULT_ADDR='https://example.com'
export VAULT_METHOD='token'
export VAULT_TOKEN='example-token'

echo 'secrets:'                       > .vault2env.yaml
echo '  FOO=secrets/default#example'  > .vault2env.yaml

# 3. run
poetry run sh -c 'echo $FOO'
```


## Configure

### Configuration file

This app searches for the file that matches following names in the current working directory and parent folders, and load the config from it. When there are more than one exists, the first one would be selected according to the order here:

1. `.vault2env.toml`[^1]
2. `.vault2env.yaml`[^2]
3. `.vault2env.yml`[^2]
4. `.vault2env.json`
5. `pyproject.toml`[^1]

[^1]: TOML format is only supported when either [tomllib](https://docs.python.org/3.11/library/tomllib.html) or [tomli](https://pypi.org/project/tomli/) is installed.
[^2]: YAML format is only supported when [PyYAML](https://pypi.org/project/PyYAML/) is installed.

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

> For most supported file format, they shared the same schema to this example. The only different is [`pyproject.toml`](./tests/fixtures/example-pyproject.toml) format- each section must placed under `tool.vault2env` section, for aligning the community practice.
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

#### Supported methods

Here's required argument(s), their accepted source, and corresponding keys:

##### `token`

| key   | config file | env var        | keyring        |
|-------|:-----------:|:---------------|:---------------|
| token | ⛔️          | `VAULT_TOKEN`  | `token/:token` |

##### `okta`

| key      | config file | env var          | keyring               |
|----------|:-----------:|:-----------------|:----------------------|
| username | `username`  | `VAULT_USERNAME` | `okta/:username`      |
| password | ⛔️          | `VAULT_PASSWORD` | `okta/YOUR_USER_NAME` |

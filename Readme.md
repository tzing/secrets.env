# secrets.env 🔓

![test result](https://github.com/tzing/secrets.env/actions/workflows/test.yml/badge.svg)

Put secrets from [Vault](https://www.vaultproject.io/) KV engine to environment variables like a `.env` loader. Without not landing data on disk.

Security is important, but don't want it to be a stumbling block. We love secret manager, but the practice of getting secrets for local development could be dangerous- some of us put the sensitive data into a shell script and source it, which brings the risk of credential leaking.

This tool is built to *plug in* secrets into development without landing data on disk. Furthermore, we can safely commit the config file into CVS, for easily reproducing the environment, and reduce the risk of uploading the secrets to the server.


## Usage

> **Note**
>
> Standard CLI usage is not implemented yet.
> Currently this app could only be used as a poetry plugin. Plugin is a poetry **1.2.0** feature, which is still in beta testing.

Get it from this repository:

```bash
# add as poetry global plugin
poetry self add 'git+https://github.com/tzing/secrets.env.git@trunk' -E toml

# add to project venv
poetry add --dev 'git+https://github.com/tzing/secrets.env.git@trunk' -E toml
```

Folowing extras avaliable:

* `yaml`: supporting YAML config
* `toml`: supporting TOML config, includes using `pyproject.toml`

If none of them are selected, this app only supports the config in JSON format.

### With poetry

You can use this package as a [poetry plugin](https://python-poetry.org/docs/master/plugins/), then this app will pull the secrets from vault on poetry command `run` and `shell`.

```bash
# 1. install plugin
poetry self add 'git+https://github.com/tzing/secrets.env.git@trunk' -E yaml

# 2. setup config
#    read configuration section below for details
export VAULT_ADDR='https://example.com'
export VAULT_METHOD='token'
export VAULT_TOKEN='example-token'

echo 'secrets:'                       > .secrets-env.yaml
echo '  FOO=secrets/default#example'  > .secrets-env.yaml

# 3. run
poetry run sh -c 'echo $FOO'
```


## Configure

### Configuration file

This app searches for the file that matches following names in the current working directory and parent folders, and load the config from it. When there are more than one exists, the first one would be selected according to the order here:

1. `.secrets-env.toml`[^1]
2. `.secrets-env.yaml`[^2]
3. `.secrets-env.yml`[^2]
4. `.secrets-env.json`
5. `pyproject.toml`[^1]

[^1]: TOML format is only supported when either [tomllib](https://docs.python.org/3.11/library/tomllib.html) or [tomli](https://pypi.org/project/tomli/) is installed.
[^2]: YAML format is only supported when [PyYAML](https://pypi.org/project/PyYAML/) is installed.

An example config in YAML format:

```yaml
# `source` configured the connection info to vault.
# This is an *optional* section- values under section are required, but you can
# provide them using environment variable.
source:
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

> For most supported file format, they shared the same schema to this example. The only different is [`pyproject.toml`](./example/pyproject.toml) format- each section must placed under `tool.secrets-env` section, for aligning the community practice.
> Visit [example folder](./example/) to read the equivalent expression in each format.

### Authentication

Vault enforce authentication during requests, so we must provide the identity in order to get the secrets.

#### Method

Secrts.env adapts several auth methods. You must specify the auth method by either config file or the environment variable `VAULT_METHOD`. Here's the format in config file:

```yaml
---
# standard layout
# arguments could be included in `auth:`
source:
  auth:
    method: okta
    username: user@example.com

---
# alternative layout
# arguments must be avaliable in other source
source:
  auth: token
```

#### Arguments

Arguments could be provided by various source: config file, environment variable and system keyring service.

We're using [keyring] package, which reads and saves the values from OSX [Keychain], KDE [KWallet], etc. For reading/saving value into keyring, use its [command line utility] with the system name `secrets.env`:

[keyring]: https://keyring.readthedocs.io/en/latest/
[Keychain]: https://en.wikipedia.org/wiki/Keychain_%28software%29
[KWallet]: https://en.wikipedia.org/wiki/KWallet
[command line utility]: https://keyring.readthedocs.io/en/latest/#command-line-utility

```bash
keyring get secrets.env token/:token
keyring set secrets.env okta/test@example.com
```

#### Supported methods

Here's required argument(s), their accepted source, and corresponding keys:

##### `token`

| key   | config file | env var        | keyring        |
|-------|:------------|:---------------|:---------------|
| token | ⛔️          | `VAULT_TOKEN`  | `token/:token` |

##### `okta`

| key      | config file | env var          | keyring               |
|----------|:------------|:-----------------|:----------------------|
| username | `username`  | `VAULT_USERNAME` | `okta/:username`      |
| password | ⛔️          | `VAULT_PASSWORD` | `okta/YOUR_USER_NAME` |

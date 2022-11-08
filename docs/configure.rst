Configure
=========

This app accepts configs in various format (with some optional dependency), here's an example config:

.. tabs::

   .. code-tab:: yaml

      source:
        url: https://example.com/

        auth:
          method: okta
          username: user@example.com

        tls:
          ca_cert: /path/ca.cert
          client_cert: /path/client.cert
          client_key: /path/client.key

      secrets:
        VAR1:
         path: kv/default
         key: example.to.value
        VAR2: "kv/default#example.to.value"

   .. code-tab:: toml

      [source]
      url = "https://example.com/"

      [source.auth]
      method = "okta"
      username = "user@example.com"

      [source.tls]
      ca_cert = "/path/ca.cert"
      client_cert = "/path/client.cert"
      client_key = "/path/client.key"

      [secrets]
      VAR1 = {path = "kv/default", key = "example.to.value"}
      VAR2 = "kv/default#example.to.value"

   .. code-tab:: json

      {
        "source": {
          "url": "https://example.com/",
          "auth": {
            "method": "okta",
            "username": "user@example.com"
          },
          "tls": {
            "ca_cert": "/path/ca.cert",
            "client_cert": "/path/client.cert",
            "client_key": "/path/client.key"
          }
        },
        "secrets": {
          "VAR1": "kv/default#example",
          "VAR2": {
            "path": "kv/default",
            "key": "example"
          }
        }
      }

.. note::

   This app also reads config from ``pyproject.toml`` in PEP-621 style.
   To use this format, use the template in TOML format and add the prefix ``tool.secrets-env`` to each section
   (e.g. change ``[secrets]`` to ``[tool.secrets-env.secrets]``).


Config file path
----------------

This app searches for the file that matches following names in the current working directory and parent folders, and load the config from it. When there are more than one exists, the first one would be selected according to the order here:

1. ``.secrets-env.toml`` [#use-toml]_
2. ``.secrets-env.yaml`` [#use-yaml]_
3. ``.secrets-env.yml`` [#use-yaml]_
4. ``.secrets-env.json``
5. ``pyproject.toml`` [#use-toml]_

.. [#use-toml] TOML format is only supported when either `tomllib <https://docs.python.org/3.11/library/tomllib.html>`_ or `tomli <https://pypi.org/project/tomli/>`_ is available.
.. [#use-yaml] YAML format is only supported when `PyYAML <https://pypi.org/project/PyYAML/>`_ is installed.


Vault connection
----------------

Vault connection information could be set in ``source`` section, or using environment variable.

.. tabs::

   .. code-tab:: yaml

      source:
        url: https://example.com/
        auth:
          method: okta
          username: user@example.com
        tls:
          ca_cert: /path/ca.cert
          client_cert: /path/client.cert
          client_key: /path/client.key

   .. code-tab:: toml

      [source]
      url = "https://example.com/"

      [source.auth]
      method = "okta"
      username = "user@example.com"

      [source.tls]
      ca_cert = "/path/ca.cert"
      client_cert = "/path/client.cert"
      client_key = "/path/client.key"


.. hint::

   To reduce context switch overhead, this tools accepts the ``VAULT_*``
   environment variables and align the behavior with Hashicorp's
   `vault <https://developer.hashicorp.com/vault/docs/commands>`_ CLI tool.

url
   *(Required)* URL to Vault.
   Could be overwritten by environment variable ``SECRETS_ENV_ADDR``.

auth
   *(Required)* Authentication information. Read `Authentication` section below.

tls
   *(Optional)* Transport layer security (TLS) configurations. Ignore this section if you don't need
   customized certificate.

   Configurations in this section includes:

   * Server side certificate ``ca_cert`` for verifying responses.
     Could be overwritten by environment variable ``SECRETS_ENV_CA_CERT``.
   * Client side certificate ``client_cert`` for communicating with vault server.
     Could be overwritten by environment variable ``SECRETS_ENV_CLIENT_CERT``.
   * Client key ``client_key``.
     If you're using some format and the client key is included in client cert, then just uses *client_cert*.
     Could be overwritten by environment variable ``SECRETS_ENV_CLIENT_KEY``.


Authentication
--------------

Vault enforce authentication during requests, so we must provide the identity in order to get the secrets.

.. tabs::

   .. code-tab:: yaml

      auth:
        method: okta
        username: user@example.com

   .. code-tab:: toml

      [source.auth]
      method = "okta"
      username = "user@example.com"

Like the ``source`` section, it is possible to complete setup auth info from a non-config file source:

.. code-block:: bash

   export SECRETS_ENV_METHOD='okta'
   export SECRETS_ENV_USERNAME='user@example.com'
   export SECRETS_ENV_PASSWORD='Ex@mp1e_P@ssw0rd'

Method
++++++

Secrets.env adapts several authentication methods. You MUST specify the method by either config file or the environment variable ``SECRETS_ENV_METHOD``.

If you do not need to store arguments in config file, then you can drop ``method`` keyword, as a shortcut:

.. tabs::

   .. code-tab:: yaml

      source:
        auth: okta

   .. code-tab:: toml

      [source]
      auth = "okta"


Arguments
+++++++++

Auth data could be provided by various source, including:

config file
   Place the config value under ``auth`` section, use the key provided in the table.

environment variable
   In most cases, environment variable could be used to overwrite the values from config file.

keyring
   We're using `keyring`_ package to read the values from system keyring (e.g. macOS `Keychain`_). For saving a value into keyring, use its `command line utility`_ with the system name ``secrets.env``:

   .. code-block:: bash

      keyring get secrets.env token/:token
      keyring set secrets.env okta/test@example.com

.. _keyring: https://keyring.readthedocs.io/en/latest/
.. _Keychain: https://en.wikipedia.org/wiki/Keychain_%28software%29
.. _command line utility: https://keyring.readthedocs.io/en/latest/#command-line-utility

prompt
   If no data found in all other sources, it prompts user for input. You can disable it by setting environment variable ``SECRETS_ENV_NO_PROMPT=True``.


Supported methods
+++++++++++++++++

Here's supported auth methods, corresponding arguments, and their accepted source:

Vault token (``token``)
~~~~~~~~~~~~~~~~~~~~~~~

Token is the most basic method to get authentication from Vault.

token
   Vault token

   * ✅ From config file: ``token``
   * ✅ From environment variable: any of ``SECRETS_ENV_TOKEN``, ``VAULT_TOKEN``
   * ✅ From keyring: ``token/:token``
   * ✅ From `token helper`_ [#token-helper]_

.. _token helper: https://www.vaultproject.io/docs/commands/token-helper
.. [#token-helper] Vault CLI stores the generated token in the ``~/.vault-token`` file after authenticated. This app reads the token from that file, but it do not create one on authenticating using this app.

Okta login (``okta``)
~~~~~~~~~~~~~~~~~~~~~

Get authentication by login to Okta.

username
   User name to login Okta

   * ✅ From config file: ``username``
   * ✅ From environment variable: ``SECRETS_ENV_USERNAME``
   * ✅ From keyring: ``okta/:username``
   * ✅ A prompt would be displayed when none of the above are provided

password
   User password to login Okta

   * ⛔️ From config file
   * ✅ From environment variable: ``SECRETS_ENV_PASSWORD``
   * ✅ From keyring: ``okta/YOUR_USER_NAME``
   * ✅ A prompt would be displayed when none of the above are provided


Secret values
-------------

The ``secrets`` section is a required section which must be written in the config file and no alternative source supported.

.. tabs::

   .. code-tab:: yaml

      secrets:
        VAR1:
         path: kv/default
         key: example.to.value

        VAR2: "kv/default#example.to.value"  # shortcut: path#key

   .. code-tab:: toml

      [secrets]
      VAR1 = {path = "kv/default", key = "example.to.value"}
      VAR2 = "kv/default#example.to.value"  # shortcut: path#key

name
   The name on left side (``VAR1``, ``VAR2``) would be the destination environment variable name after the secrets is loaded.

path
   Path to read secret from vault.

key
   Key is the field name to identify which value to extract. For nested structure, join the keys with dots.

Configure
=========

Example config
--------------

.. tabs::

   .. code-tab:: yaml

      # `source` section configured Vault connection info.
      # All values in this section could be provided using other sources (e.g. environment variable),
      # so it is possible to run secrets.env app without this section.
      source:
        # Vault address
        # Could be replaced using environment variable ``SECRETS_ENV_ADDR`` or ``VAULT_ADDR``
        url: https://example.com/

        # Authentication info
        # Schema for authentication could be various, read 'authentication' section.
        auth:
          method: okta
          username: user@example.com

        # Transport layer security (TLS) configurations.
        tls:
          # Server side certificate for verifying responses.
          ca_cert: /path/ca.cert

          # Client side certificate for communicating with vault server.
          client_cert: /path/client.cert
          client_key: /path/client.key

      # `secrets` lists the environment variable name, and the path the get the secret value
      secrets:
        # The key (VAR1) is the environment variable name to install the secret
        VAR1:
         # Path to read secret from vault
         path: kv/default

         # Field name to identify which value to extract, as we may have multiple values in
         # single secret in KV engine.
         # For nested structure, join the keys with dots.
         key: example.to.value

        # Syntax sugar: path#key
        VAR2: "kv/default#example.to.value"

   .. code-tab:: toml

      # `source` section configured Vault connection info.
      # All values in this section could be provided using other sources (e.g. environment variable),
      # so it is possible to run secrets.env app without this section.
      [source]

      # Vault address
      # Could be replaced using environment variable ``SECRETS_ENV_ADDR`` or ``VAULT_ADDR``
      url = "https://example.com/"

      # Authentication info
      # Schema for authentication could be various, read 'authentication' section.
      [source.auth]
      method = "okta"
      username = "user@example.com"

      # Transport layer security (TLS) configurations.
      [source.tls]
      # Server side certificate for verifying responses.
      ca_cert = "/path/ca.cert"

      # Client side certificate for communicating with vault server.
      client_cert = "/path/client.cert"
      client_key = "/path/client.key"

      # `secrets` lists the environment variable name, and the path the get the secret value
      [secrets]
      # The key (VAR1) is the environment variable name to install the secret. ``path`` is the secret
      # path to read from vault. And ``key`` is the field name to identify which value to extract.
      # For nested structure, join the keys with dots.
      VAR1 = {path = "kv/default", key = "example.to.value"}

      # Syntax sugar: path#key
      VAR2 = "kv/default#example.to.value"


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


.. Import other docs
.. include:: vault.rst
.. include:: auth.rst

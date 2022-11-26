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

Format
^^^^^^

Method
""""""

Secrets.env adapts several authentication methods. You should specify the method by either config file or the environment variable ``SECRETS_ENV_METHOD``.
When ``method`` is not set, it tries to use ``token`` as the default method.

If you do not need to store other arguments in config file, then you can drop ``method`` keyword, as a shortcut:

.. tabs::

   .. code-tab:: yaml

      source:
        auth: okta

   .. code-tab:: toml

      [source]
      auth = "okta"


Arguments
"""""""""

Auth data could be provided by various source, including:

config file
   Place the config value under ``auth`` section, use the key provided in the table.

environment variable
   In most cases, environment variable could be used to overwrite the values from config file.

keyring
   This source requires :ref:`keyring-integration`. It stores and reads the credentials from system keyring.

   This source is always ignored when the optional dependency is not installed. And you can disable it by setting environment variable ``SECRETS_ENV_NO_KEYRING=True``.

prompt
   If no data found in all other sources, it prompts user for input. You can disable it by setting environment variable ``SECRETS_ENV_NO_PROMPT=True``.

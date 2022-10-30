.. _authentication:

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

Config file
   Place the config value under ``auth`` section, use the key provided in the table.

Environment variable
   In most cases, environment variable could be used to overwrite the values from config file.

Keyring
   We're using `keyring`_ package to read the values from system keyring (e.g. macOS `Keychain`_). For saving a value into keyring, use its `command line utility`_ with the system name ``secrets.env``:

   .. code-block:: bash

      keyring get secrets.env token/:token
      keyring set secrets.env okta/test@example.com

.. _keyring: https://keyring.readthedocs.io/en/latest/
.. _Keychain: https://en.wikipedia.org/wiki/Keychain_%28software%29
.. _command line utility: https://keyring.readthedocs.io/en/latest/#command-line-utility

Prompt
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

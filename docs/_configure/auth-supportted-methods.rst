Supported methods
"""""""""""""""""

In the following paragraphs, they shows the supported authentication methods and their corresponding arguments.


Vault token
^^^^^^^^^^^

:method: ``token``

Token is the most basic method to get authentication from Vault.
This is also the default method applied when ``method`` is not set.

token
   Vault token

   * ⛔️ From config file
   * ✅ From environment variable: any of ``SECRETS_ENV_TOKEN``, ``VAULT_TOKEN``
   * ✅ From `token helper`_ [#token-helper]_
   * ✅ From keyring: ``token/:token``

.. _token helper: https://www.vaultproject.io/docs/commands/token-helper
.. [#token-helper] Vault CLI stores the generated token in the ``~/.vault-token`` file after authenticated. This app reads the token from that file, but it do not create one on authenticating using this app.


Basic auth
^^^^^^^^^^

:method: ``basic``

Use user name and password to get authentication.

username
   User name to login

   * ✅ From environment variable: ``SECRETS_ENV_USERNAME``
   * ✅ From config file: ``username``
   * ✅ From keyring: ``basic/username``
   * ✅ A prompt would be displayed when none of the above are provided

password
   User password to login

   * ⛔️ From config file
   * ✅ From environment variable: ``SECRETS_ENV_PASSWORD``
   * ✅ From keyring: ``basic/password``
   * ✅ A prompt would be displayed when none of the above are provided


LDAP
^^^^

:method: ``ldap``

Login with LDAP credentials.

username
   User name to login

   * ✅ From environment variable: ``SECRETS_ENV_USERNAME``
   * ✅ From config file: ``username``
   * ✅ From keyring: ``ldap/username``
   * ✅ A prompt would be displayed when none of the above are provided

password
   User password to login

   * ⛔️ From config file
   * ✅ From environment variable: ``SECRETS_ENV_PASSWORD``
   * ✅ From keyring: ``ldap/password``
   * ✅ A prompt would be displayed when none of the above are provided


Okta
^^^^

:method: ``okta``

Get authentication by login to Okta.

username
   User name to login Okta

   * ✅ From environment variable: ``SECRETS_ENV_USERNAME``
   * ✅ From config file: ``username``
   * ✅ From keyring: ``okta/username``
   * ✅ A prompt would be displayed when none of the above are provided

password
   User password to login Okta

   * ⛔️ From config file
   * ✅ From environment variable: ``SECRETS_ENV_PASSWORD``
   * ✅ From keyring: ``okta/password``
   * ✅ A prompt would be displayed when none of the above are provided


OpenID Connect
^^^^^^^^^^^^^^

:method: ``oidc``

Get authentication via configured OIDC provider using your web browser.

role
   *(Optional)* OIDC role. Will use default role if not set.

   * ✅ From environment variable: ``SECRETS_ENV_ROLE``
   * ✅ From config file: ``role``

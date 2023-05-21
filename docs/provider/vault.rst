Vault KV Provider
=================

Provider that retrieves value(s) from HashiCorp Vault's `KV secrets engine`_.

.. _KV secrets engine: https://developer.hashicorp.com/vault/docs/secrets/kv

type
   ``vault`` *or none*

.. hint::

   This provider serves as the default provider for this app.
   If you configure your settings without specifying a ``type`` keyword, this provider will be automatically used.


Configuration template
----------------------

.. tabs::

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
      BRIEF = "secret/default#example.to.value"
      FULL = {path = "secret/default", field = "example.to.value"}

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
        FULL:
         path: secret/default
         field: example.to.value

        BRIEF: "secret/default#example.to.value"

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
          "FULL": {
            "path": "secret/default",
            "field": "example.to.value"
          },
          "BRIEF": "secret/default#example.to.value"
        }
      }


Connection parameters
---------------------

.. hint::

   In order to minimize context switching overhead, this tool accepts environment variables prefixed with ``VAULT_`` and aligns its behavior with HashiCorp's `Vault CLI tool`_.

   .. _Vault CLI tool: https://developer.hashicorp.com/vault/docs/commands

The connection parameters can be set in ``source`` section in the configuration file.
They can also be set via environment variables.
The parameters includes:

``url`` *(required)*
   URL to Vault.
   Could be set via environment variable ``SECRETS_ENV_ADDR`` or ``VAULT_ADDR``.

``auth`` *(required)*
   Authentication information. Read `Authentication`_ section below.

``tls``
   Transport layer security (TLS) configurations.
   Ignore this section if you don't need customized certificate.


Authentication
++++++++++++++

Vault enforce authentication during requests, so we must provide the identity in order to get the secrets.

Authentication method
^^^^^^^^^^^^^^^^^^^^^
The authentication method is a required input, and can be set using the ``method`` keyword or the ``SECRETS_ENV_METHOD`` environment variable.
If ``method`` is not specified, the default method is `Vault token`_.
Additional inputs may be required depending on the selected method.

The supportted authentication methods are:

* `Vault token`_
* `Basic auth`_
* `LDAP`_
* `Okta`_
* `OpenID Connect`_
* `RADIUS`_

Keyring integration
^^^^^^^^^^^^^^^^^^^
When :ref:`keyring add-on <keyring-addon>` is enabled, the provider reads the credentials from system keyring.
You can disable it by setting environment variable ``SECRETS_ENV_NO_KEYRING=True``.

Prompt input
^^^^^^^^^^^^
This provider has been enhanced to receive parameters from various source.
One of them is prompt, it prompts you for input when some required are not found in all the other source(s).
You can disable it by setting environment variable ``SECRETS_ENV_NO_PROMPT=True``.

Shortcut
^^^^^^^^
Once all other parameters have been provided by non-config sources, you can set ``auth`` to the method name as the shortcut:

.. tabs::

   .. code-tab:: toml

      [source]
      auth = "okta"

   .. code-tab:: yaml

      source:
        auth: okta


TLS configuration
+++++++++++++++++

TLS configurations includes:

``ca_cert``
   Server side certificate for verifying responses.
   Could be set via environment variable ``SECRETS_ENV_CA_CERT`` or ``VAULT_CACERT``.

``client_cert``
   Client side certificate for communicating with vault server.
   Could be set via environment variable ``SECRETS_ENV_CLIENT_CERT`` or ``VAULT_CLIENT_CERT``.

``client_key``
   Client side private key to be used with client side certificate.

   If you're using some format and the client key is included in client cert, then please ignore this field.
   This field could be set via environment variable ``SECRETS_ENV_CLIENT_KEY`` or ``VAULT_CLIENT_KEY``.


Secret values
-------------

For vault provider, secret values must be explicitly paired with both a path and a field:

``path`` *(required)*
   Path to read secret from vault.

``field`` *(required)*
   Field name to identify which value to extract. For nested structure, join the fields with dots.

.. tabs::

   .. code-tab:: toml

      [secrets]
      CLASSIC = {path = "secret/default", field = "example.to.value"}
      SHORTCUT = "secret/default#example.to.value"  # shortcut: path#field

   .. code-tab:: yaml

      secrets:
        CLASSIC:
         path: secret/default
         field: example.to.value

        SHORTCUT: "secret/default#example.to.value"  # shortcut: path#field


.. _authentication-methods:

Supported Authentication methods
--------------------------------

Vault token
+++++++++++

:method: ``token``

Token is the most basic method to get authentication from Vault.
This is also the default method applied when ``method`` is not set.
It's parameters is:

``token`` *(required)*
   Vault token

   * ⛔️ From config file
   * 🆗 From environment variable: any of ``SECRETS_ENV_TOKEN``, ``VAULT_TOKEN``
   * 🆗 From `token helper`_ [#token-helper]_
   * 🆗 From keyring: ``token``

.. _token helper: https://www.vaultproject.io/docs/commands/token-helper
.. [#token-helper] Vault CLI stores the generated token in the ``~/.vault-token`` file after authenticated. This app reads the token from that file, but it do not create one on authenticating using this app.

Basic auth
++++++++++

:method: ``basic``

Use user name and password to get authentication.

``username`` *(required)*
   User name to login

   * 🆗 From environment variable: ``SECRETS_ENV_USERNAME``
   * 🆗 From config file: ``username``
   * 🆗 Prompt

``password`` *(required)*
   User password to login

   * ⛔️ From config file
   * 🆗 From environment variable: ``SECRETS_ENV_PASSWORD``
   * 🆗 From keyring: ``userpass/YOUR_USER_NAME``
   * 🆗 Prompt

LDAP
++++

:method: ``ldap``

Login with `LDAP`_ credentials.

.. _LDAP: https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol

``username`` *(required)*
   User name to login

   * 🆗 From environment variable: ``SECRETS_ENV_USERNAME``
   * 🆗 From config file: ``username``
   * 🆗 Prompt

``password`` *(required)*
   User password to login

   * ⛔️ From config file
   * 🆗 From environment variable: ``SECRETS_ENV_PASSWORD``
   * 🆗 From keyring: ``ldap/YOUR_USER_NAME``
   * 🆗 Prompt

Okta
++++

:method: ``okta``

Get authentication by login to `Okta`_.

.. _Okta: https://www.okta.com/

``username`` *(required)*
   User name to login Okta

   * 🆗 From environment variable: ``SECRETS_ENV_USERNAME``
   * 🆗 From config file: ``username``
   * 🆗 Prompt

``password`` *(required)*
   User password to login Okta

   * ⛔️ From config file
   * 🆗 From environment variable: ``SECRETS_ENV_PASSWORD``
   * 🆗 From keyring: ``okta/YOUR_USER_NAME``
   * 🆗 Prompt


OpenID Connect
++++++++++++++

:method: ``oidc``

Get authentication via configured `OpenID Connect`_ provider using your web browser.

.. _OpenID Connect: https://openid.net/connect/

``role``
   OIDC role. Will use default role if not set.

   * 🆗 From environment variable: ``SECRETS_ENV_ROLE``
   * 🆗 From config file: ``role``


RADIUS
++++++

:method: ``radius``

Authentication using an existing `RADIUS`_ server that accepts the `PAP authentication scheme`_.

.. _RADIUS: https://en.wikipedia.org/wiki/RADIUS
.. _PAP authentication scheme: https://en.wikipedia.org/wiki/Password_Authentication_Protocol

``username`` *(required)*
   User name to login

   * 🆗 From environment variable: ``SECRETS_ENV_USERNAME``
   * 🆗 From config file: ``username``
   * 🆗 Prompt

``password`` *(required)*
   User password to login

   * ⛔️ From config file
   * 🆗 From environment variable: ``SECRETS_ENV_PASSWORD``
   * 🆗 From keyring: ``radius/YOUR_USER_NAME``
   * 🆗 Prompt

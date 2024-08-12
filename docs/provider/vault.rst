Vault KV Provider
=================

This provider fetches secrets from HashiCorp Vault's `KV secrets engine`_ and imports them into environment variables.
It represents one of the most common and straightforward use cases for secrets.env.

.. _KV secrets engine: https://developer.hashicorp.com/vault/docs/secrets/kv

.. tip::

   To streamline workflow and minimize context switching, this provider supports configuration via environment variables.

   By default, it retrieves configuration from environment variables prefixed with ``SECRETS_ENV_``.
   However, for alignment with the official `Vault CLI tool`_, it can also be set up to read from environment variables prefixed with ``VAULT_``.

   .. _Vault CLI tool: https://developer.hashicorp.com/vault/docs/commands


Configuration layout
--------------------

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         name = "strongbox"
         type = "vault"
         url = "https://vault.example.com"
         proxy = "http://proxy:3128"

         [sources.auth]
         method = "okta"
         username = "user@example.com"

         [sources.tls]
         ca_cert = "/path/ca.cert"
         client_cert = "/path/client.cert"
         client_key = "/path/client.key"

         [sources.teleport]
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         user = "demo-user"
         app = "my-app"

         [[secrets]]
         name = "DEMO_TOKEN"
         source = "strongbox"
         path = "secret/default"
         field = "token"

         [[secrets]]
         name = "NESTED_SECRET"
         source = "strongbox"
         path = "secret/default"
         field = [
            "subpath",
            "to",
            "secret",
         ]

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - name: strongbox
             type: vault
             url: https://vault.example.com
             auth:
               method: okta
               username: user@example.com
             proxy: http://proxy:3128
             tls:
               ca_cert: /path/ca.cert
               client_cert: /path/client.cert
               client_key: /path/client.key
             teleport:
               proxy: teleport.example.com
               cluster: dev.example.com
               user: demo-user
               app: my-app

         secrets:
           - name: DEMO_TOKEN
             source: strongbox
             path: secret/default
             field: token

           - name: NESTED_SECRET
             source: strongbox
             path: secret/default
             field:
               - subpath
               - to
               - secret

   .. tab-item:: json

      .. code-block:: json

         {
           "sources": [
             {
               "name": "strongbox",
               "type": "vault",
               "url": "https://vault.example.com",
               "auth": {
                 "method": "okta",
                 "username": "user@example.com"
               },
               "proxy": "http://proxy:3128",
               "tls": {
                 "ca_cert": "/path/ca.cert",
                 "client_cert": "/path/client.cert",
                 "client_key": "/path/client.key"
               },
               "teleport": {
                 "proxy": "teleport.example.com",
                 "cluster": "dev.example.com",
                 "user": "demo-user",
                 "app": "my-app"
               }
             }
           ],
           "secrets": [
             {
               "name": "DEMO_TOKEN",
               "source": "strongbox",
               "path": "secret/default",
               "field": "token"
             },
             {
               "name": "NESTED_SECRET",
               "source": "strongbox",
               "path": "secret/default",
               "field": [
                 "subpath",
                 "to",
                 "secret"
               ]
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         name = "strongbox"
         type = "vault"
         url = "https://vault.example.com"
         proxy = "http://proxy:3128"

         [tool.secrets-env.sources.auth]
         method = "okta"
         username = "user@example.com"

         [tool.secrets-env.sources.tls]
         ca_cert = "/path/ca.cert"
         client_cert = "/path/client.cert"
         client_key = "/path/client.key"

         [tool.secrets-env.sources.teleport]
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         user = "demo-user"
         app = "my-app"

         [[tool.secrets-env.secrets]]
         name = "DEMO_TOKEN"
         source = "strongbox"
         path = "secret/default"
         field = "token"

         [[tool.secrets-env.secrets]]
         name = "NESTED_SECRET"
         source = "strongbox"
         path = "secret/default"
         field = [
            "subpath",
            "to",
            "secret",
         ]


Environment variables
---------------------

.. envvar:: SECRETS_ENV_ADDR

   The URL to the Vault server. Overrides the ``url`` field.

.. envvar:: SECRETS_ENV_CA_CERT

   Path to the server side certificate for verifying responses. Overrides the ``tls.ca_cert`` field.

.. envvar:: SECRETS_ENV_CLIENT_CERT

   Path to the client certificate for authenticating to the server. Overrides the ``tls.client_cert`` field.

.. envvar:: SECRETS_ENV_CLIENT_KEY

   Specifies the path to the client's private key for authenticating to the server. Overrides the ``tls.client_key`` field.

.. envvar:: SECRETS_ENV_NO_PROMPT

   Disables the prompt for username / password when using :ref:`vault.meth.login-meths`.

.. envvar:: SECRETS_ENV_PASSWORD

   The password to authenticate with. Used by :ref:`vault.meth.login-meths`.

.. envvar:: SECRETS_ENV_PROXY

   Use the specified proxy to access Vault. Overrides the ``proxy`` field.

.. envvar:: SECRETS_ENV_ROLE

   Role name used by :ref:`vault.meth.oidc` and :ref:`vault.meth.kubernetes`. Overrides :ref:`vault.auth.role` field.

.. envvar:: SECRETS_ENV_TOKEN

   The token to use for authentication. Used by :ref:`vault.meth.token` method.

.. envvar:: SECRETS_ENV_USERNAME

   The username to authenticate with. Overrides :ref:`vault.auth.username` field.

Source section
--------------

   A field name followed by a bookmark icon (:octicon:`bookmark`) indicates that it is a required parameter.

``url`` :octicon:`bookmark`
+++++++++++++++++++++++++++

The URL to the Vault server.

You can set this field using the environment variables :envvar:`SECRETS_ENV_ADDR` or ``VAULT_ADDR``.
However, if the :ref:`vault.teleport` section is configured, it will be ignored.

``auth`` :octicon:`bookmark`
++++++++++++++++++++++++++++

Defines the method and associated arguments for authenticating with Vault.

.. _vault.auth.method:

``auth.method`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The method to use for authentication.

Accepted values are:

- ``kubernetes``, applying the :ref:`vault.meth.kubernetes` method
- ``ldap``, applying the :ref:`vault.meth.ldap` method
- ``oidc``, applying the :ref:`vault.meth.oidc` method
- ``okta``, applying the :ref:`vault.meth.okta` method
- ``radius``, applying the :ref:`vault.meth.radius` method
- ``token``, applying the :ref:`vault.meth.token` method
- ``userpass``, applying the :ref:`vault.meth.userpass` method

.. _vault.auth.role:

``auth.role``
^^^^^^^^^^^^^

Role name used by :ref:`vault.meth.oidc` and :ref:`vault.meth.kubernetes`.

.. _vault.auth.username:

``auth.username``
^^^^^^^^^^^^^^^^^

Username used by :ref:`vault.meth.login-meths`.

Shortcut
^^^^^^^^

In certain scenarios, only the ``method`` field may be required.
For instance, when utilizing :ref:`vault.meth.okta` and providing ``username`` through another method such as environment variables, you can simply set the ``method`` directly for the ``auth`` field:

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         name = "strongbox"
         type = "vault"
         url = "https://vault.example.com"
         auth = "okta"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - name: strongbox
             type: vault
             url: https://vault.example.com
             auth: okta

``proxy``
+++++++++

Use the specified proxy to access Vault.

Could be set via environment variable :envvar:`SECRETS_ENV_PROXY`, ``VAULT_PROXY_ADDR``, ``VAULT_HTTP_PROXY`` or uses `standard proxy variables`_.

.. _standard proxy variables: https://www.python-httpx.org/environment_variables/#proxies

.. important::

   You must specify protocol for proxy URL. A typical input could be ``http://proxy`` or ``http://proxy:3128``.
   Further, the proxy URL for the ``https://`` addresses should still be ``http://`` scheme in most cases.

``tls``
+++++++

Transport layer security (TLS) configurations.

``tls.ca_cert``
^^^^^^^^^^^^^^^

Path to the server side certificate for verifying responses.

This value could be set via environment variable :envvar:`SECRETS_ENV_CA_CERT` or ``VAULT_CACERT``.

``tls.client_cert``
^^^^^^^^^^^^^^^^^^^

Path to the client certificate for authenticating to the server.

This value could be set via environment variable :envvar:`SECRETS_ENV_CLIENT_CERT` or ``VAULT_CLIENT_CERT``.

``tls.client_key``
^^^^^^^^^^^^^^^^^^

Specifies the path to the client's private key for authenticating to the server.
If your client certificate already includes the client key in its format, please disregard this field.

This value could be set via environment variable :envvar:`SECRETS_ENV_CLIENT_KEY` or ``VAULT_CLIENT_KEY``.

.. _vault.teleport:

``teleport``
++++++++++++

Configuration for :ref:`vault.feat.teleport`.

``teleport.app`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify the name of the Teleport application to request connection information from.
This field is necessary when utilizing :ref:`vault.feat.teleport`.

``teleport.proxy``
^^^^^^^^^^^^^^^^^^

Address to Teleport `proxy <https://goteleport.com/docs/architecture/proxy/>`_ service.

``teleport.cluster``
^^^^^^^^^^^^^^^^^^^^

Teleport cluster to connect.

``teleport.user``
^^^^^^^^^^^^^^^^^

Teleport user name.


.. _vault.token-helper:

Token helper
------------

Vault offers a feature known as `token helper`_, which stores the Vault token on the disk.

Secrets.env now includes support for this feature.
It means you won't have to provide the token again after the initial login until it expires.

* The token helper file is shared among applications, allowing the token obtained by secrets.env to be used with the Vault CLI, and vice versa.

* The token helper login attempt takes precedence over any other authentication method.

  Secrets.env first attempts to use the token helper to communicate with the Vault server.
  If the token is not found or has expired, it will then fall back to the configured authentication method.

* Secrets.env DOES NOT consider vault configuration.
  Instead, it solely reads the token from the default path, which is ``~/.vault-token``.

.. _token helper: https://developer.hashicorp.com/vault/docs/commands/token-helper


Authentication methods
----------------------

Vault enforces authentication during requests, requiring an identity to access secrets.

By specifying the :ref:`vault.auth.method` field, the associated authentication method will be applied.

.. _vault.meth.kubernetes:

Kubernetes auth
+++++++++++++++

:method: ``kubernetes``

Authenticate with Vault using the Kubernetes service account token.
This method corresponds to the `Kubernetes auth method`_ in Vault.

.. _Kubernetes auth method: https://developer.hashicorp.com/vault/docs/auth/kubernetes

Role
^^^^

Role name. Could be retrieved via:

1. Environment variable :envvar:`SECRETS_ENV_ROLE`
2. From :ref:`vault.auth.role` field

.. _vault.meth.login-meths:

Login auth methods
++++++++++++++++++

Login authentication methods in secrets.env pertains to a group of authentication methods that mandate a username and password combination.

These authentication methods share the same arguments: username and password.
Here are the details on how we retrieve the values:

Username :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The username to authenticate with. Could be set via:

1. Environment variable :envvar:`SECRETS_ENV_USERNAME`
2. From :ref:`vault.auth.username` field
3. From user configuration, which is set via command :ref:`cmd.set`
4. The app prompts for the username if it's not provided.

   If you want to disable the prompt, set the environment variable :envvar:`SECRETS_ENV_NO_PROMPT` to ``true``.

Password :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The password to authenticate with. Could be retrieved via:

1. Environment variable :envvar:`SECRETS_ENV_PASSWORD`
2. User keyring, which is set via command :ref:`cmd.set`
3. The app prompts for the password if it's not provided.

   If you want to disable the prompt, set the environment variable :envvar:`SECRETS_ENV_NO_PROMPT` to ``true``.

.. _vault.meth.ldap:

:octicon:`chevron-right` LDAP auth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:method: ``ldap``

Login with `LDAP`_ credentials.
This method corresponds to the `LDAP auth method`_ in Vault.

.. _LDAP: https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
.. _LDAP auth method: https://developer.hashicorp.com/vault/docs/auth/ldap

.. _vault.meth.okta:

:octicon:`chevron-right` Okta auth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:method: ``okta``

Authenticated through `Okta`_.
This method corresponds to the `Okta auth method`_ in Vault.

.. _Okta: https://www.okta.com/
.. _Okta auth method: https://developer.hashicorp.com/vault/docs/auth/okta

.. _vault.meth.radius:

:octicon:`chevron-right` RADIUS auth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:method: ``radius``

Authentication using an existing `RADIUS`_ server that accepts the `PAP authentication scheme`_.
This method corresponds to the `RADIUS auth method`_ in Vault.

.. _RADIUS: https://en.wikipedia.org/wiki/RADIUS
.. _PAP authentication scheme: https://en.wikipedia.org/wiki/Password_Authentication_Protocol
.. _RADIUS auth method: https://developer.hashicorp.com/vault/docs/auth/radius

.. _vault.meth.userpass:

:octicon:`chevron-right` Userpass auth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:method: ``userpass``

A straightforward method for authenticating with Vault using a combination of username and password.
This method corresponds to the `userpass auth method`_ in Vault.

.. _userpass auth method: https://developer.hashicorp.com/vault/docs/auth/userpass

.. _vault.meth.oidc:

OpenID Connect
++++++++++++++

:method: ``oidc``

Get authentication via configured `OpenID Connect`_ provider using your web browser.
This method corresponds to the `JWT/OIDC auth method`_ in Vault.

.. _OpenID Connect: https://openid.net/connect/
.. _JWT/OIDC auth method: https://developer.hashicorp.com/vault/docs/auth/jwt

Role
^^^^

Role name. Could be retrieved via:

1. Environment variable :envvar:`SECRETS_ENV_ROLE`
2. From :ref:`vault.auth.role` field

.. _vault.meth.token:

Token auth
++++++++++

:method: ``token``

`Token auth`_ is one of the simplest ways to authenticate with Vault.

It's worth noting that secrets.env first tries to retrieve the token using the :ref:`vault.token-helper` before resorting to this authentication method.
This method is mainly for manual token input and accepts tokens only from environment variables.

.. _token auth: https://developer.hashicorp.com/vault/docs/auth/token

Token :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^

The only argument used for this method is the token itself,
which must be set via environment variables :envvar:`SECRETS_ENV_TOKEN` or ``VAULT_TOKEN``.

.. _vault.feat.teleport:

Teleport integration
--------------------

If your Vault is secured using `Teleport`_, you can employ the this feature to establish a connection with Vault.

.. _Teleport: https://goteleport.com/

Enabling
++++++++

.. important::

   To use this feature, additional dependencies are needed.
   Please check the :doc:`../advanced/teleport` page for further information.

Once :ref:`vault.teleport` configurations are configured, the Vault provider will request access from Teleport and utilize it to establish a connection to Vault.

Example
+++++++

This configuration instructs secrets.env to request access for "my-vault" from Teleport and establish a connection to the application:

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         type = "vault"

         [sources.teleport]
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         app = "my-vault"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           type: vault
           teleport:
             proxy: teleport.example.com
             cluster: dev.example.com
             app: my-vault

Since Teleport manages the connection, any URL and TLS configuration provided in the config file will be ignored.

Configuration
+++++++++++++

Just like with the :doc:`teleport`, the ``app`` field is always mandatory for this functionality.

Other fields are optional. Read :ref:`vault.teleport` section above for more information.


Secrets section
---------------

The configurations within the ``secrets`` section determine which secrets are to be read.

``path`` :octicon:`bookmark`
++++++++++++++++++++++++++++

The path to the secret in Vault.

``field`` :octicon:`bookmark`
+++++++++++++++++++++++++++++

Indicates the field within the secret to be imported.

For a nested secret object, you have two options:

1. Specify a list of fields to traverse the hierarchy.
2. Use a dot-separated string to represent the path to the desired field.

For example, consider a secret object like this:

.. code-block:: json

   {
     "prod": {
       "username": "admin"
     },
     "dev": {
       "username": "user"
     }
     "stg.demo-1": {
       "username": "user"
     }
   }

You can use any of the following methods to import the "username" for the "prod" environment:

* Specify ``["prod", "username"]``
* Use the string ``prod.username``

  If the field name contains a dot, you should enclose the field name in double quotes, like ``"stg.demo-1".username``.


Simplified layout
-----------------

This provider accepts strings in the format ``path#field`` to represent the path and field of a value. With the simplified layout, you can define config more concisely:

.. tab-set::

   .. tab-item:: toml :bdg:`simplified`
      :sync: toml

      .. code-block:: toml

         [source]
         type = "vault"
         url = "https://vault.example.com"
         auth = "oidc"

         [secrets]
         PROD_TOKEN = "secret/default#prod.token"
         DEV_TOKEN = { path = "secret/default", field = "dev.token" }

   .. tab-item:: yaml :bdg:`simplified`
      :sync: yaml

      .. code-block:: yaml

          source:
            type: vault
            url: https://vault.example.com
            auth: oidc

          secrets:
            PROD_TOKEN: secret/default#prod.token
            DEV_TOKEN:
              path: secret/default
              field: dev.token

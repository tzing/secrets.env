Vault Connection
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
   *(Required)* Authentication information. Read :ref:`authentication` section below.

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

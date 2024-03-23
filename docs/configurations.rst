Configurations
==============

The configuration file is vital for secrets.env, enabling secure retrieval and storage of credentials.

Filename
--------

The app looks for a file with one of the following names in the current working directory and its parent folders, and loads the configuration from it.

If multiple files exist, the app will select the first one based on the order listed below:

1. ``.secrets-env.toml``
2. ``.secrets-env.yaml`` [#use-yaml]_
3. ``.secrets-env.yml`` [#use-yaml]_
4. ``.secrets-env.json``
5. ``pyproject.toml``

.. [#use-yaml]
   YAML format is supported only if you have installed secrets.env with pip extra ``[yaml]``.


Layout
------

The configuration file should contain ``sources`` section to specify the secret provider, and its connection parameters, and ``secrets`` section to list the value(s) to be loaded:

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         type = "vault"
         name = "my-vault"
         url = "https://example.com"
         auth = "token"

         [secrets]
         DEMO_USERNAME = {source = "my-vault", path = "secrets/default", field = "username"}

   .. tab-item:: toml :bdg:`simplified`

      .. code-block:: toml

         [source]
         type = "vault"
         url = "https://example.com"
         auth = "token"

         [secrets]
         DEMO_USERNAME = {path = "secrets/default", field = "username"}

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - type: vault
             name: my-vault
             url: https://example.com
             auth: token

         secrets:
           DEMO_USERNAME:
             source: my-vault
             field: username
             path: secrets/default

   .. tab-item:: yaml :bdg:`simplified`

      .. code-block:: yaml

         source:
           type: vault
           url: https://example.com
           auth: token

         secrets:
           DEMO_USERNAME:
             field: username
             path: secrets/default

   .. tab-item:: json
      :sync: json

      .. code-block:: json

         {
           "sources": [
             {
               "type": "vault",
               "name": "my-vault",
               "url": "https://example.com",
               "auth": "token"
             }
           ],
           "secrets": {
             "DEMO_USERNAME": {
               "source": "my-vault",
               "path": "secrets/default",
               "field": "username"
             }
           }
         }

   .. tab-item:: pyproject.toml
      :sync: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         type = "vault"
         name = "my-vault"
         url = "https://example.com"
         auth = "token"

         [tool.secrets-env.secrets]
         DEMO_USERNAME = {source = "my-vault", path = "secrets/default", field = "username"}

.. tip::

   The section names ``source`` / ``secrets`` can be either singular or plural.
   The application will recognize them regardless of the naming convention.

.. admonition:: About "simplified" layout

   When there's only one source in the configuration, users can opt for a "simplified" layout.
   In this layout, the source section can be formatted as a straightforward table instead of a list, and the ``name`` field can be excluded.
   Similarly, in the secrets section, users can also choose to remove the ``source`` field for clarity.

   The example section primarily showcases simplified versions in a few formats, but it's worth noting that the tool also supports various other formats.


Source section
--------------

Source section specifies secret provider information.

The ``type`` field in the configuration specifies the provider to be utilized, while the ``name`` field allows users to assign a custom name.
Additional arguments are passed into the corresponding provider, so users should refer to the provider's documentation for detailed information on these arguments.

The supported provider types includes:

- ``plain``

  This creates a :doc:`provider/plain`, allowing values to be read directly from the configuration. Essentially, it functions as a ``.env`` loader.

- ``teleport``

  This creates a :doc:`provider/teleport`, designed to fetch credentials from `Gravitational Teleport <https://goteleport.com/teleport/>`_.

- ``vault``

  This creates a :doc:`provider/vault`, capable of retrieving secrets from `HashiCorp Vault <https://www.vaultproject.io/>`_.


Secret section
--------------

The secrets section lists key-value pairs where the keys correspond to the environment variable names in which the values will be stored.
The specific format of the value depends on the secret provider being used.

When multiple providers are installed, it's necessary to include the ``source`` field to indicate the provider from which the value should be fetched.
And the remaining fields are passed into the relevant provider.

In the example, the value of ``DEMO_USERNAME`` is fetched from the ``my-vault`` source, and the ``path`` and ``field`` fields are passed into the the correspond provider.

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [secrets]
         DEMO_USERNAME = {source = "my-vault", path = "secrets/default", field = "username"}

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         secrets:
           DEMO_USERNAME:
             source: my-vault
             field: username
             path: secrets/default


Simplified specification
^^^^^^^^^^^^^^^^^^^^^^^^

When the configuration is arranged in the simplified layout, users have the option to specify secrets in a simplified manner:

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [secrets]
         DEMO_USERNAME = "secrets/default#username"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         secrets:
           DEMO_USERNAME: "secrets/default#username"

A simplified approach involves representing the entire secret specification using a string.
The specific format of this string depends on the chosen provider.

For instance, the Vault provider recommends using the format ``path#field`` as demonstrated in this example.

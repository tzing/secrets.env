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

         [[secrets]]
         name = "DEMO_USERNAME"
         source = "my-vault"
         path = "secrets/default"
         field = "username"

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
           - name: DEMO_USERNAME
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
             {
               "name": "DEMO_USERNAME",
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

         [[tool.secrets-env.secrets]]
         name = "DEMO_USERNAME"
         source = "my-vault"
         path = "secrets/default"
         field = "username"

.. tip::

   The section names ``source`` / ``secrets`` can be either singular or plural.
   The application will recognize them regardless of the naming convention.

.. admonition:: Simplified layout

   The configuration file can be simplified under certain conditions. Read sections below for more information.


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


Single source
^^^^^^^^^^^^^

When there's only one source in the configuration, several things can be omitted:

* Field ``name`` can be excluded from source section.
* Field ``source`` can be omitted from the secrets section.
* The source metadata can be set directly under the source(s) key (rather than under a list).

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. grid:: 1 1 2 2

         .. grid-item::

            .. code-block:: toml

               # Standard layout
               [[sources]]
               type = "vault"
               name = "my-vault"
               url = "https://example.com"
               auth = "token"

               [[secrets]]
               name = "DEMO"
               source = "my-vault"
               path = "secrets/default"
               field = "token"

         .. grid-item::

            .. code-block:: toml

               # Simplified layout
               [source]
               type = "vault"
               url = "https://example.com"
               auth = "token"

               [[secrets]]
               name = "DEMO"
               path = "secrets/default"
               field = "token"

   .. tab-item:: yaml
      :sync: yaml

      .. grid:: 1 1 2 2

         .. grid-item::

            .. code-block:: yaml

               # Standard layout
               sources:
                 - type: vault
                   name: my-vault
                   url: https://example.com
                   auth: token

               secrets:
                 - name: DEMO
                   source: my-vault
                   path: secrets/default
                   field: token

         .. grid-item::

            .. code-block:: yaml

               # Simplified layout
               source:
                 type: vault
                 url: https://example.com
                 auth: token

               secrets:
                 - name: DEMO
                   path: secrets/default
                   field: token


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

Certain providers offer a simplified method for specifying secrets retrieval.
In these instances, you can represent the secret specification as a string.
Simply assign the desired string to the ``value`` field:

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

The specific format of the string depends on the provider you've selected.
For example, the Vault provider suggests using the format ``path#field``, as illustrated in this example.

Use key-value pairs
^^^^^^^^^^^^^^^^^^^

The secrets section can be formatted either as a list or as a table.

If you choose to use a table format, the key-value pairs should be directly listed under the secrets key.
Each key will be treated as the environment variable name, and the corresponding value will represent the secret specification.

Here are some examples in different formats, demonstrating the same configuration:

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. grid:: 1 1 2 2

         .. grid-item::

            .. code-block:: toml

               # List
               [[secrets]]
               name = "DEMO"
               path = "secrets/default"
               field = "token"

         .. grid-item::

            .. code-block:: toml

               # Table
               [secrets]
               DEMO = {path = "secrets/default", field = "token"}

         .. grid-item::

            .. code-block:: toml

                  # List, simplified specification
                  [[secrets]]
                  name = "DEMO"
                  value = "secrets/default#token"

         .. grid-item::

               .. code-block:: toml

                  # Table, simplified specification
                  [secrets]
                  DEMO = "secrets/default#token"

   .. tab-item:: yaml
      :sync: yaml

      .. grid:: 1 1 2 2

         .. grid-item::

            .. code-block:: yaml

               # List
               secrets:
                 - name: DEMO
                   path: secrets/default
                   field: token

         .. grid-item::

               .. code-block:: yaml

                  # Table
                  secrets:
                    DEMO:
                      path: secrets/default
                      field: token

         .. grid-item::

               .. code-block:: yaml

                  # List, simplified specification
                  secrets:
                    - name: DEMO
                      value: "secrets/default#token"

         .. grid-item::

               .. code-block:: yaml

                  # Table, simplified specification
                  secrets:
                    DEMO: "secrets/default#token"


Global configurations
---------------------

Here are some global configurations that can impact the behavior of secrets.env.

Environment variables
^^^^^^^^^^^^^^^^^^^^^

.. envvar:: SECRETS_ENV_CONFIG_FILE

   Specify the configuration file to be loaded.

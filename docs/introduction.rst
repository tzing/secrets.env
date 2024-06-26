Introduction
============

Secrets.env is a command-line tool tailored for environment variable management.
Its functionality is optimized for seamless integration with secrets management systems, such as `Hashicorp Vault`_.

.. _Hashicorp Vault: https://www.vaultproject.io/


Requirements
------------

Secrets.env requires **Python 3.9+**.


Installation
------------

Install it using `pipx`_ / `pip`_, use it as a standalone CLI tool:

.. code-block:: bash

   pipx install secrets.env

Unlock additional functionalities by installing secrets.env with extras. Choose from several options tailored to enhance your experience:

- ``all`` - Install everything below for comprehensive functionality.
- ``keyring`` - Enable :doc:`keyring add-on <advanced/keyring>` for secure credential storage.
- ``teleport`` - Opt for the :doc:`teleport add-on <advanced/teleport>` to streamline operations and reduce overhead when connecting through `Gravitational Teleport`_.
- ``yaml`` - Gain support for YAML configuration, ensuring flexibility and ease of use.

Select the extras that best suit your needs to optimize your secrets.env experience.

.. code-block:: bash

   pipx install 'secrets.env[yaml]'

.. hint::

   Remember to quote the extras to ensure that the shell interprets the brackets correctly.

.. _pipx: https://pipx.pypa.io/stable/
.. _pip: https://pip.pypa.io/en/stable/
.. _Gravitational Teleport: https://goteleport.com/


Configuration
-------------

The configuration file is crucial, providing essential details for the tool to read credentials and securely store them.

.. tab-set::

   .. tab-item:: toml

      .. code-block:: toml

         # file: .secrets-env.toml
         [[sources]]
         type = "vault"
         url = "https://example.com"
         auth = "token"

         [[secrets]]
         name = "DEMO_USERNAME"
         path = "secrets/default"
         field = "username"

         [[secrets]]
         name = "DEMO_PASSWORD"
         path = "secrets/default"
         field = "password"

   .. tab-item:: yaml

      .. code-block:: yaml

         # file: .secrets-env.yaml
         sources:
           - type: vault
             url: https://example.com
             auth: token

         secrets:
           - name: DEMO_USERNAME
             path: secrets/default
             field: username

           - name: DEMO_PASSWORD
             path: secrets/default
             field: password

      .. note::

         YAML format is not enabled by default. See installation instructions above.

   .. tab-item:: json

      .. code-block:: json

         // file: .secrets-env.json
         {
           "sources": [
             {
               "type": "vault",
               "url": "https://example.com",
               "auth": "token"
             }
           ],
           "secrets": [
             {
               "name": "DEMO_USERNAME",
               "path": "secrets/default",
               "field": "username"
             },
             {
               "name": "DEMO_PASSWORD",
               "path": "secrets/default",
               "field": "password"
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         # file: pyproject.toml
         [[tool.secrets-env.sources]]
         type = "vault"
         url = "https://example.com"
         auth = "token"

         [[tool.secrets-env.secrets]]
         name = "DEMO_USERNAME"
         path = "secrets/default"
         field = "username"

         [[tool.secrets-env.secrets]]
         name = "DEMO_PASSWORD"
         path = "secrets/default"
         field = "password"

This configuration instructs secrets.env to retrieve two values from the Vault and assign them to ``DEMO_USERNAME`` and ``DEMO_PASSWORD``.


Run
---

Secrets.env retrieves values from configured sources and assigns them as environment variables.

Once the operation is finished, the secrets are cleared from the environment to prevent exposure to other processes.

.. code-block:: bash

   secrets.env run -- ./my-script

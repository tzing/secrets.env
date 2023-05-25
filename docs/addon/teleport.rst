.. _teleport-addon:

Teleport
========

`Teleport`_ is an open-source tool for providing zero trust access to servers and cloud applications.

This addon communicates with the Teleport client to obtain certificate for you when there are some requests need it.

.. _Teleport: https://goteleport.com/


Enable
------

This addon requires Teleport client (``tsh``).

For macOS users, you can get it from homebrew:

.. code-block:: bash

   brew install tsh

For other users, please read `official document <https://goteleport.com/docs/installation/>`_ for the instructions.

*(Optional)* Install this app with extras ``teleport`` for reuse the certificate in some communications:

.. tabs::

   .. code-tab:: bash pip

      pip install 'secrets.env[teleport]'

   .. code-tab:: bash poetry plugin

      poetry self add secrets.env -E teleport

.. _use-teleport-addon:

Use Teleport adapter
--------------------

Teleport uses short-lived certificates to authenticate users and services - including the secret manager.

By adding the prefix ``teleport+`` to the type field in the provider configuration, the addon automatically retrieves the certificate from Teleport and applies the TLS configuration.

Example
+++++++

In this configuration, secrets.evn is configured to communicate with the Teleport proxy *example.com* specifically for the application *demo*, and then apply the URL and TLS configuration to a Vault provider.

.. tabs::

   .. code-tab:: toml

      [source]
      type = "teleport+vault"

      [source.teleport]
      proxy = "example.com"
      app = "demo"

   .. code-tab:: yaml

      source:
        type: teleport+vault
        teleport:
          proxy: example.com
          app: demo

Parameters
++++++++++

All parameters should be placed under ``source.teleport`` section.

``app`` *(required)*
   Application name to request certificate for.

``proxy``
   Address to Teleport `proxy <https://goteleport.com/docs/architecture/proxy/>`_ service.

``user``
   Teleport user name.

Shortcut
++++++++

As Teleport stores information on disk, the only necessary information for this addon is the app name.
Hence, for such use cases, we can conveniently set the app name directly in the ``teleport`` field.

.. tabs::

   .. code-tab:: toml

      [source]
      type = "teleport+vault"
      teleport = "demo"

   .. code-tab:: yaml

      source:
        type: teleport+vault
        teleport: demo

Adapted provider
++++++++++++++++

- :ref:`vault-provider`

Teleport Provider
=================

This provider reads connection information of a `Teleport`_-protected application and pastes them to environment variables.

.. _Teleport: https://goteleport.com/

type
   ``teleport``

.. important::

   This provider requires extra dependency to work, read :doc:`Teleport add-on <../addon/teleport>` for more details.


Configuration template
----------------------

.. note::

   These templates use :ref:`multiple sources config` format.

.. tabs::

   .. code-tab:: toml

      [[source]]
      name = "tsh"
      type = "teleport"
      proxy = "teleport.example.com"
      app = "demo"

      [secrets]
      HOST = { source = "tsh", field = "uri" }
      CLIENT_CERT = { source = "tsh", field = "client-cert", format = "path" }

   .. code-tab:: yaml

      source:
      - name: tsh
        type: teleport
        proxy: teleport.example.com
        app: demo

      secrets:
        HOST:
          field: uri
          source: tsh
        CLIENT_CERT:
          field: client-cert
          format: path
          source: tsh

   .. code-tab:: json

      {
        "source": [
          {
            "name": "tsh",
            "type": "teleport",
            "proxy": "teleport.example.com",
            "app": "demo"
          }
        ],
        "secrets": {
          "HOST": {
            "source": "tsh",
            "field": "uri"
          },
          "CLIENT_CERT": {
            "source": "tsh",
            "field": "client-cert",
            "format": "path"
          }
        }
      }

   .. code-tab:: toml pyproject.toml

      [[tool.secrets-env.source]]
      name = "tsh"
      type = "teleport"
      proxy = "teleport.example.com"
      app = "demo"

      [tool.secrets-env.secrets]
      HOST = { source = "tsh", field = "uri" }
      CLIENT_CERT = { source = "tsh", field = "client-cert", format = "path" }


Source section
--------------

You must specify the application in this section.

This provider will run the Teleport client in the background to fetch information.
The following parameters will be filled by Teleport when not specified.

``app`` *(required)*
   Application name to request connection information for.

``proxy``
   Address to Teleport `proxy <https://goteleport.com/docs/architecture/proxy/>`_ service.

``cluster``
   Teleport cluster to connect.

``user``
   Teleport user name.

Values
------

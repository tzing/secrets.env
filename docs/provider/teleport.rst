Teleport Provider
=================

This provider reads connection information of a `Teleport`_-protected application and pastes them to environment variables.

This component is introduced to do the *tsh login* and *export* things for me:

.. code-block:: bash

   tsh app login --proxy=proxy.blah.com my-app
   export SSL_CERT_FILE=$(tsh app config --proxy=proxy.blah.com -f=ca my-app)

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
      CLIENT_CERT = { source = "tsh", field = "cert", format = "path" }

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
          field: cert
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
            "field": "cert",
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
      CLIENT_CERT = { source = "tsh", field = "cert", format = "path" }


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

The configurations in ``secrets`` section specified the item to output:

``field`` *(required)*
   Item to output. It could be:

   ``uri``
      URI to the app.
   ``ca``
      Certificate authority (CA) certificate. The certificate to verify the peer.
   ``cert``
      Client certificate.
   ``key``
      Private key.
   ``cert+key``
      Client certificate and private key bundle.

``format``
   Output format for certificates. The value is discarded when ``field`` is set to ``uri``.
   The value could be:

   ``path`` *(default)*
      Path to the certificate file. Note this file would be burned after secrets.env session terminated.
   ``pem``
      Output text in `PEM`_ format.

.. _PEM: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail

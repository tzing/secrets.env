Teleport Provider
=================

This provider retrieves connection information from the `Teleport client tool`_ and transfers it to environment variables.

Introduced to automate tasks such as ``tsh login`` and ``export``, this component eliminates the need for manual copy-paste commands like:

.. code-block:: bash

   tsh app login --proxy=teleport.example.com my-app
   export SSL_CERT_FILE=$(tsh app config --proxy=teleport.example.com -f=ca my-app)

.. _Teleport client tool: https://goteleport.com/docs/connect-your-client/tsh/

.. important::

   To use this provider, additional dependencies are needed.
   Please check the :doc:`../advanced/teleport` page for further information.


Configuration layout
--------------------

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         name = "tsh"
         type = "teleport"
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         app = "my-app"

         [[secrets]]
         name = "HOST"
         source = "tsh"
         field = "uri"

         [[secrets]]
         name = "SSL_CERT_FILE"
         source = "tsh"
         field = "ca"
         format = "path"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - name: tsh
             type: teleport
             proxy: teleport.example.com
             cluster: dev.example.com
             app: my-app

         secrets:
           - name: HOST
             source: tsh
             field: uri
           - name: SSL_CERT_FILE
             source: tsh
             field: ca
             format: path

   .. tab-item:: json

      .. code-block:: json

         {
           "sources": [
             {
               "name": "tsh",
               "type": "teleport",
               "proxy": "teleport.example.com",
               "cluster": "dev.example.com",
               "app": "my-app"
             }
           ],
           "secrets": [
             {
               "name": "HOST",
               "source": "tsh",
               "field": "uri"
             },
             {
               "name": "SSL_CERT_FILE",
               "source": "tsh",
               "field": "ca",
               "format": "path"
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         name = "tsh"
         type = "teleport"
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         app = "my-app"

         [[tool.secrets-env.secrets]]
         name = "HOST"
         source = "tsh"
         field = "uri"

         [[tool.secrets-env.secrets]]
         name = "SSL_CERT_FILE"
         source = "tsh"
         field = "ca"
         format = "path"


Source section
--------------

   A field name followed by a bookmark icon (:octicon:`bookmark`) indicates that it is a required parameter.

To retrieve connection information, it's necessary to provide the application name.
If the remaining parameters are left unspecified, Teleport will automatically populate them with default values.

``app`` :octicon:`bookmark`
+++++++++++++++++++++++++++

Application name to request connection information for.

``proxy``
+++++++++

Address to Teleport `proxy <https://goteleport.com/docs/architecture/proxy/>`_ service.

``cluster``
+++++++++++

Teleport cluster to connect.

``user``
++++++++

Teleport user name.


Secrets section
---------------

The configurations within the ``secrets`` section determine which items are to be output.

``field`` :octicon:`bookmark`
+++++++++++++++++++++++++++++

Specifies the item to output, which could be:

``uri``
   URI to the application.
``ca``
   Certificate authority (CA) certificate used to verify the peer.
``cert``
   Client certificate.
``key``
   Private key.
``cert+key``
   Bundle containing both client certificate and private key.

``format``
++++++++++

Determines the format in which certificates are outputted.
The value is ignored when ``field`` is set to ``uri``, and could be:

``path`` :bdg-success-line:`default`
   Path to the certificate file.
   Secrets.env will create a temporary file and set the environment variable to its path.
``pem``
   Outputs text in `PEM <https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail>`_ format.

Simplified layout
-----------------

When utilizing this provider with simplified configuration, the string value will be interpreted as ``field``, and the default format will be applied:

.. tab-set::

   .. tab-item:: toml :bdg:`simplified`
      :sync: toml

      .. code-block:: toml

         [source]
         type = "teleport"
         proxy = "teleport.example.com"
         cluster = "dev.example.com"
         app = "my-app"

         [secrets]
         HOST = "uri"
         SSL_CERT_FILE = "ca"

   .. tab-item:: yaml :bdg:`simplified`
      :sync: yaml

      .. code-block:: yaml

         source:
           type: teleport
           proxy: teleport.example.com
           cluster: dev.example.com
           app: my-app

         secrets:
           HOST: uri
           SSL_CERT_FILE: ca

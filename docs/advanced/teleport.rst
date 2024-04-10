Teleport Support
================

Gravitational's `Teleport`_ is a tool that helps you securely access servers, applications, and various resources while maintaining a zero-trust approach to security.

Secrets.env complements Teleport by allowing you to fetch certificates from the Teleport client and utilize them to authenticate with different services.

.. _Teleport: https://goteleport.com/


Enabling
--------

In addition to optional dependencies, using this feature necessitates having the Teleport client (``tsh``) installed on the same machine where secrets.env is operating.

1. To set up the Teleport client, refer to the official installation guide for detailed instructions:

   https://goteleport.com/docs/installation/

2. Installing secrets.env with the extras ``teleport``:

   .. tab-set::

      .. tab-item:: pip

         .. code-block:: bash

            pip install 'secrets.env[teleport]'

      .. tab-item:: poetry

         .. code-block:: bash

            poetry self add secrets.env --extras teleport


Certificate provider
--------------------

Teleport acts as a secure gateway to access servers and applications.
Occasionally, you might need to connect local applications to remote services.
In such cases, you'll utilize the Teleport client to retrieve certificates and integrate them into your application.

Secrets.env includes a :doc:`../provider/teleport` that interacts with the Teleport client to obtain certificates and deliver them to the application.


TLS adapter
-----------

.. error::

   This feature is temporary disabled. It still works in the stable version.

This feature is used by :doc:`../provider/vault` for fetching certificates from Teleport.

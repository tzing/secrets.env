Secrets.env
===========

Secrets.env is the bridge between `Vault <https://www.vaultproject.io/>`_ and your app.

It put values from Vault KV engine to environment variables like a ``.env`` loader, without landing credentials on disk.

.. image:: imgs/screenshot.png

Security is important, but don't want it to be a stumbling block. We love secret manager, but the practice of getting secrets for local development could be a trouble.

This app is built to *plug in* secrets into development without landing data on disk, easily reproduce the environment, and reduce the risk of uploading the secrets to the server.


User guide
----------

.. toctree::
   :maxdepth: 1

   quick-start
   configurations
   addon/index
   api/index

.. toctree::
   :caption: Links
   :hidden:

   PyPI page <https://pypi.org/project/secrets-env/>
   GitHub repository <https://github.com/tzing/secrets.env/>

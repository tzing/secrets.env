.. secrets.env documentation master file, created by
   sphinx-quickstart on Wed Sep 21 21:24:44 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Secrets.env
===========

Put secrets from `Vault <https://www.vaultproject.io/>`_ KV engine to environment variables like a ``.env`` loader, without landing data on disk.

.. image:: imgs/screenshot.png

Security is important, but don't want it to be a stumbling block. We love secret manager, but the practice of getting secrets for local development could be a trouble.

This app is built to *plug in* secrets into development without landing data on disk, easily reproduce the environment, and reduce the risk of uploading the secrets to the server.


User guide
----------

.. toctree::
   :maxdepth: 1

   quick-start
   configure
   integrations

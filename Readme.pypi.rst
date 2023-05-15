Secrets.env
===========

Secrets.env is the bridge between `Vault <https://www.vaultproject.io/>`_ and your app.

It put values from Vault KV engine to environment variables like a ``.env`` loader, without landing credentials on disk.

.. code-block:: bash

   $ cat .secrets-env.yaml
   source:
     url: http://localhost:8200
     auth: token

   secrets:
     EXAMPLE:
       path: secrets/example
       field: foo

   $ secrets.env run sh -c 'echo \$EXAMPLE = $EXAMPLE'
   [secrets_env] Read secrets.env config from /Users/tim_shih/.secrets-env.yaml
   [secrets_env] 🔑 1 secrets loaded
   $EXAMPLE = hello

Security is important, but don't want it to be a stumbling block. We love secret manager, but the practice of getting secrets for local development could be a trouble.

This app is built to *plug in* secrets into development without landing data on disk, easily reproduce the environment, and reduce the risk of uploading the secrets to the server.

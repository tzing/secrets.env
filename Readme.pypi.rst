Secrets.env
===========

Put secrets from `Vault <https://www.vaultproject.io/>`_ KV engine to environment variables like a ``.env`` loader, without landing data on disk.

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

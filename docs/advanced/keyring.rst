Keyring Support
===============

Secrets.env seamlessly integrates with the `keyring`_ library, providing a secure solution for managing credentials.

.. _keyring: https://keyring.readthedocs.io/en/latest/


Enabling
--------

Install secrets.env with extra ``keyring`` to enable this feature:

.. tab-set::

   .. tab-item:: pipx

      .. code-block:: bash

         # for the first time installation
         pipx install 'secrets.env[keyring]'

         # if you have already installed secrets.env
         pipx inject secrets.env 'secrets.env[keyring]'

   .. tab-item:: pip

      .. code-block:: bash

         pip install 'secrets.env[keyring]'

   .. tab-item:: poetry

      .. tip::

         The dependencies is already satisfied when you install with poetry.


Environment variables
---------------------

.. envvar:: SECRETS_ENV_NO_KEYRING

    When set to ``true``, the keyring feature will be disabled.

Save credential to keyring
--------------------------

Use CLI command :ref:`cmd.set` to save credential to keyring.

Read credential from keyring
----------------------------

This feature is used by :doc:`../provider/vault` for loading password.

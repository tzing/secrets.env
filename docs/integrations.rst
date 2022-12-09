Integrations
============

Secrets.env works best with some other tools. Here's currently available integrations:

.. _keyring-integration:

Keyring integration
-------------------

This integration adopts `keyring`_ package to store and read the values from system keyring (e.g. macOS `Keychain`_).

Enabling
^^^^^^^^

You need to install secrets.env with extra ``keyring`` to enable this feature:

.. code-block:: bash

    pip install 'secrets.env[keyring]'

Usage
^^^^^

Currently we don't provide tool to save the credential. You need to use keyring's `command line utility`_.

Use the service name ``secrets.env`` and the keys listed in :ref:`authentication-methods` section:

.. code-block:: bash

   keyring get secrets.env token/:token
   keyring set secrets.env okta/test@example.com

.. _keyring: https://keyring.readthedocs.io/en/latest/
.. _Keychain: https://en.wikipedia.org/wiki/Keychain_%28software%29
.. _command line utility: https://keyring.readthedocs.io/en/latest/#command-line-utility


Plugin system
-------------

Secrets.env is now integrated with `pluggy <https://pluggy.readthedocs.io/en/stable/>`_.
You can use it to inject customized logics into secrets.env without modified the code base.

Avaliable hooks
^^^^^^^^^^^^^^^

.. autoclass:: secrets_env.hooks.HookSpec
   :members:

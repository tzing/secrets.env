.. _keyring-addon:

Keyring
=======

This add-on adopts `keyring`_ package to store and read the values from system keyring (e.g. macOS `Keychain`_).

.. _keyring: https://keyring.readthedocs.io/en/latest/
.. _Keychain: https://en.wikipedia.org/wiki/Keychain_%28software%29


Enable
------

You need to install secrets.env with extra ``keyring`` to enable this feature:

.. code-block:: bash

    pip install 'secrets.env[keyring]'


Usage
-----

Add value
+++++++++

Currently we don't provide tool to save the credential. Please use keyring's `command line utility`_ to manage values.

Use the service name ``secrets.env`` and the keys listed in :ref:`authentication-methods` section.

.. code-block:: bash

   keyring set secrets.env okta/test@example.com

.. _command line utility: https://keyring.readthedocs.io/en/latest/#command-line-utility

Temporary disable
+++++++++++++++++

By setting environment environment variable ``SECRETS_ENV_NO_KEYRING`` to any of ``true`` /  ``t`` / ``yes`` / ``y`` / ``1`` (case insensitive), keyring add-on would be disabled.

.. code-block:: bash

   export SECRETS_ENV_NO_KEYRING=True

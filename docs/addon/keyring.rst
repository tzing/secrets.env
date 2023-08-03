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

When used this app as a :doc:`Poetry plugin</addon/poetry>`, there is no need for the optional dependency. Keyring is integrated into poetry core, ensuring constant feature availability.

Usage
-----

Add/remove value
++++++++++++++++

Use :ref:`command-keyring` command.

Temporary disable
+++++++++++++++++

By setting environment environment variable ``SECRETS_ENV_NO_KEYRING`` to any of ``true`` /  ``t`` / ``yes`` / ``y`` / ``1`` (case insensitive), keyring add-on would be disabled.

.. code-block:: bash

   export SECRETS_ENV_NO_KEYRING=True

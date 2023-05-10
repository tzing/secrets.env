Integrations
============

Secrets.env works best with some tools. Here's currently available integrations:

Poetry integration
------------------

`Poetry`_ is an awesome tool for dependency management.
This app could be used as its `plugin`_, and loads the secrets into environment for you.

.. _Poetry: https://python-poetry.org/
.. _plugin: https://python-poetry.org/docs/master/plugins/

Enable
++++++

Run this command and poetry will install it:

.. code-block:: sh

   poetry self add secrets.env

YAML config feature is not enabled by default (You can still use TOML and JSON). If you need it, then install with extras:

.. code-block:: sh

   poetry self add secrets.env -E yaml

Refer to :ref:`installation` for the options.

Usage
+++++

This plugin pull secrets to environment variable on poetry command ``run`` and ``shell``:

.. code-block:: sh

   $ poetry shell
   🔑 2 secrets loaded
   Spawning shell within /some/where

You might read the message like *n secrets loaded* in stderr when running the commands above.


.. _keyring-integration:

Keyring integration
-------------------

This integration adopts `keyring`_ package to store and read the values from system keyring (e.g. macOS `Keychain`_).

Enable
++++++

You need to install secrets.env with extra ``keyring`` to enable this feature:

.. code-block:: bash

    pip install 'secrets.env[keyring]'

Usage
+++++

Currently we don't provide tool to save the credential. You need to use keyring's `command line utility`_ to add a value.

Use the service name ``secrets.env`` and the keys listed in :ref:`authentication-methods` section:

.. code-block:: bash

   keyring set secrets.env okta/test@example.com

.. _keyring: https://keyring.readthedocs.io/en/latest/
.. _Keychain: https://en.wikipedia.org/wiki/Keychain_%28software%29
.. _command line utility: https://keyring.readthedocs.io/en/latest/#command-line-utility

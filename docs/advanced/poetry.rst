Poetry Support
==============

`Poetry`_ is an excellent tool for managing dependencies.
Secrets.env is designed to function as a `Poetry plugin`_, seamlessly loading secrets into the environment for you.

.. _Poetry: https://python-poetry.org/
.. _Poetry plugin: https://python-poetry.org/docs/master/plugins/


Enabling
--------

.. note::

   Please be aware that even if you've installed secrets.env via pip, you still need to execute the above command to activate it in Poetry.

   Poetry stores plugin packages separately and does not retain installed packages in the current environment.

To use this feature, make sure you have Poetry version 1.2 or higher installed.

Run the following command to instruct Poetry to install it:

.. code-block:: bash

   poetry self add secrets.env

Note that YAML config format is not enabled by default (while TOML and JSON are enabled by default). If you require YAML support, install it with extras:

.. code-block:: bash

   poetry self add secrets.env --extras yaml

Read :doc:`../introduction` for more details on optional dependencies.


Usage
-----

After enabling the plugin, secrets.env is automatically invoked when you run `poetry run`_ or `poetry shell`_.

It scans for a valid configuration file following the same strategy outlined in :doc:`../configurations`.
If one is located, it injects values into the environment during the environment creation process.

.. _poetry run: https://python-poetry.org/docs/cli/#run
.. _poetry shell: https://python-poetry.org/docs/cli/#shell

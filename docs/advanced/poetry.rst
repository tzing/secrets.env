Poetry Support
==============

`Poetry`_ is an excellent tool for managing dependencies.
Secrets.env is designed to function as a `Poetry plugin`_, seamlessly loading secrets into the environment for you.

.. _Poetry: https://python-poetry.org/
.. _Poetry plugin: https://python-poetry.org/docs/plugins/


Enabling as a global plugin
---------------------------

.. note::

   Please be aware that poetry are usually installed in a standalone environment, and the plugin must be installed in that environment.

   This means even if you've installed secrets.env via pip/pipx, you might still need to execute the following command to activate it in Poetry.

The installation command depends on how you installed Poetry:

.. tab-set::

   .. tab-item:: With pipx
      :sync: pipx

      When your Poetry installation is managed by pipx, you can enable the plugin with the following command:

      .. code-block:: bash

         pipx inject poetry secrets.env

   .. tab-item:: Others
      :sync: self-add

      When Poetry is installed via other methods, you can utilize the `self add`_ command to enable the plugin:

      .. code-block:: bash

         poetry self add secrets.env

      .. _self add: https://python-poetry.org/docs/cli/#self-add

If you need optional dependencies, such as YAML support, you can install them with extras:

.. tab-set::

   .. tab-item:: With pipx
      :sync: pipx

      .. code-block:: bash

         pipx inject poetry 'secrets.env[yaml]'

   .. tab-item:: Others
      :sync: self-add

      .. code-block:: bash

         poetry self add secrets.env --extras yaml

Read :doc:`../introduction` for more details on optional dependencies.


Enabling as a project plugin
----------------------------

Starting from Poetry 2.0, you can enable plugins on a per-project basis.

To enable secrets.env as a project plugin, add the following to your ``pyproject.toml``:

.. code-block:: toml

   [tool.poetry.requires-plugins]
   secrets-env = ">1.0"


Usage
-----

After enabling the plugin, secrets.env is automatically invoked when you run `poetry run`_ or `poetry shell`_.

It scans for a valid configuration file following the same strategy outlined in :doc:`../configurations`.
If one is located, it injects values into the environment during the environment creation process.

.. _poetry run: https://python-poetry.org/docs/cli/#run
.. _poetry shell: https://python-poetry.org/docs/cli/#shell

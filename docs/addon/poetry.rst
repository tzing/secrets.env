Poetry
======

`Poetry`_ is an awesome tool for dependency management.
This app could be used as its `plugin`_, and loads the secrets into environment for you.

.. _Poetry: https://python-poetry.org/
.. _plugin: https://python-poetry.org/docs/master/plugins/

Enable
------

Run this command and poetry will install it:

.. code-block:: sh

   poetry self add secrets.env

YAML config feature is not enabled by default (You can still use TOML and JSON). If you need it, then install with extras:

.. code-block:: sh

   poetry self add secrets.env -E yaml

Refer to :ref:`installation` for the options.

Usage
-----

This plugin pull secrets to environment variable on poetry command ``run`` and ``shell``:

.. tabs::

   .. code-tab:: sh Run

      $ poetry run echo 'hello world'
      🔑 2 secrets loaded
      hello world

   .. code-tab:: sh Shell

      $ poetry shell
      🔑 2 secrets loaded
      Spawning shell within /some/where

You might read the message like *n secrets loaded* in stderr when running the commands above.

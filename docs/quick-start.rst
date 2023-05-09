Quick start
===========

Installation
------------

This app is available on PyPI as `secrets-env <https://pypi.org/project/secrets-env/>`_.

Install from pip:

.. code-block:: bash

    pip install 'secrets.env[all]'

Or you can add it as `poetry <https://python-poetry.org/>`_ plugin:

.. code-block:: bash

    poetry self add secrets.env

Certain features are not activated by default. Here are the dependency groups you can use:

* ``all`` - *install everything below*
* ``yaml`` - supporting YAML config

Create config
-------------

This app can receive configurations from different sources. Here's a simple example, and we'll provide you with additional information later.

.. tabs::

   .. code-tab:: toml

      # file: .secrets-env.toml
      [source]
      type = "vault"
      url = "https://example.com"
      auth = "token"

      [secrets]
      VAR1 = {path = "secrets/default", field = "example-1"}
      VAR2 = "secrets/default#example-2"

   .. code-tab:: yaml

      # file: .secrets-env.yaml
      source:
        type: vault
        url: https://example.com
        auth: token

      secrets:
        VAR1:
          path: secrets/default
          field: example-1
        VAR2: secrets/default#example-2

This config directs secrets.env to read 2 values from the Vault and load them into ``VAR1`` and ``VAR2``, respectively.

Note that credentials should never be included in the config file. Instead, you should set an environment variable for authentication in such case.

.. code-block:: bash

   export SECRETS_ENV_TOKEN=...

Run
---

You can use this app either as a command line tool or as a `poetry plugin <https://python-poetry.org/docs/master/plugins/)>`_:

.. tabs::

   .. tab:: CLI

      Loads secrets to environment variable then runs the command::

         secrets.env run -- some-app-that-needs-secret --args foo bar

   .. tab:: Poetry Plugin

      Pull secrets to environment variable on poetry command `run <https://python-poetry.org/docs/cli/#run>`_ and `shell <https://python-poetry.org/docs/cli/#shell>`_::

         poetry run some-app-that-needs-secret --args foo bar

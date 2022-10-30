Quick start
===========

Installation
------------

This app is available on PyPI as `secrets-env <https://pypi.org/project/secrets-env/>`_.

Install from pip:

.. code-block:: python

    pip install secrets.env -E all

Or you can add it as `poetry <https://python-poetry.org/>`_ plugin:

.. code-block:: python

    poetry self add secrets.env -E toml

Some functionalities are not enabled by default. Following extras are available:

* ``all`` - *install everything below*
* ``yaml`` - supporting YAML config
* ``toml`` - supporting TOML config, includes ``pyproject.toml`` [\*]

.. note::

   As `tomllib <https://docs.python.org/3.11/library/tomllib.html>`_ is now a
   builtin library in python. TOML format would be natively supported if you run
   secrets.env in python 3.11 and above.


Add config
----------

This app accepts various source and format as the config.
It's using environment variable for Vault information and TOML format for target secrets, but this is not the only option.

Use environment variable for Vault information:

.. code-block:: bash

    export SECRETS_ENV_ADDR='https://example.com'
    export SECRETS_ENV_METHOD='token'
    export SECRETS_ENV_TOKEN='example-token'

And list the desired secret path and key in a config file:

.. tabs::

   .. code-tab:: yaml

      # file: .secrets-env.yaml
      secrets:
        VAR1:
          path: secrets/default
          key: example-1
        VAR2: secrets/default#example-2

   .. code-tab:: toml

      # file: .secrets-env.toml
      [secrets]
      VAR1 = {path = "secrets/default", key = "example-1"}
      VAR2 = "secrets/default#example-2"

Read :doc:`/configure/index` for more details.


Run
---

This app could be used as a command line tool:

.. code-block:: bash

   secrets.env run -- some-app-that-needs-secret --args foo bar

It loads the secrets, run the command, then forget the secrets.

Or use it as a `poetry plugin <https://python-poetry.org/docs/master/plugins/)>`_:

.. code-block:: bash

   poetry run some-app-that-needs-secret --args foo bar

This app will pull the secrets from vault on poetry command `run <https://python-poetry.org/docs/cli/#run>`_ and `shell <https://python-poetry.org/docs/cli/#shell>`_.

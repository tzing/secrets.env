Installation
============

.. toctree::
   :maxdepth: 2
   :caption: Contents:

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
   builtin library in python. TOML feature would be natively supported if you run
   secrets.env in python 3.11 and above.

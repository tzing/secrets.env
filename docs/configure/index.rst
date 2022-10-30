Configure
=========

This app accepts configs in various format (with some optional dependency), here's an example config:

.. tabs::

   .. code-tab:: yaml

      source:
        url: https://example.com/

        auth:
          method: okta
          username: user@example.com

        tls:
          ca_cert: /path/ca.cert
          client_cert: /path/client.cert
          client_key: /path/client.key

      secrets:
        VAR1:
         path: kv/default
         key: example.to.value
        VAR2: "kv/default#example.to.value"

   .. code-tab:: toml

      [source]
      url = "https://example.com/"

      [source.auth]
      method = "okta"
      username = "user@example.com"

      [source.tls]
      ca_cert = "/path/ca.cert"
      client_cert = "/path/client.cert"
      client_key = "/path/client.key"

      [secrets]
      VAR1 = {path = "kv/default", key = "example.to.value"}
      VAR2 = "kv/default#example.to.value"

   .. code-tab:: json

      {
        "source": {
          "url": "https://example.com/",
          "auth": {
            "method": "okta",
            "username": "user@example.com"
          },
          "tls": {
            "ca_cert": "/path/ca.cert",
            "client_cert": "/path/client.cert",
            "client_key": "/path/client.key"
          }
        },
        "secrets": {
          "VAR1": "kv/default#example",
          "VAR2": {
            "path": "kv/default",
            "key": "example"
          }
        }
      }

.. note::

   This app also reads config from ``pyproject.toml`` in PEP-621 style.
   To use this format, use the template in TOML format and add the prefix ``tool.secrets-env`` to each section
   (e.g. change ``[secrets]`` to ``[tool.secrets-env.secrets]``).

Config file path
----------------

This app searches for the file that matches following names in the current working directory and parent folders, and load the config from it. When there are more than one exists, the first one would be selected according to the order here:

1. ``.secrets-env.toml`` [#use-toml]_
2. ``.secrets-env.yaml`` [#use-yaml]_
3. ``.secrets-env.yml`` [#use-yaml]_
4. ``.secrets-env.json``
5. ``pyproject.toml`` [#use-toml]_

.. [#use-toml] TOML format is only supported when either `tomllib <https://docs.python.org/3.11/library/tomllib.html>`_ or `tomli <https://pypi.org/project/tomli/>`_ is available.
.. [#use-yaml] YAML format is only supported when `PyYAML <https://pypi.org/project/PyYAML/>`_ is installed.


.. Import other docs
.. include:: vault.rst
.. include:: auth.rst
.. include:: secrets.rst

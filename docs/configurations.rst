Configurations
==============

Filename
--------

The app looks for a file with one of the following names in the current working directory and its parent folders, and loads the configuration from it.
If multiple files exist, the app will select the first one based on the order listed below:

== ===================== =================
#  Filename              Format
== ===================== =================
1  ``.secrets-env.toml`` TOML
2  ``.secrets-env.yaml`` YAML [#use-yaml]_
3  ``.secrets-env.yml``  YAML [#use-yaml]_
4  ``.secrets-env.json`` JSON
5  ``pyproject.toml``    TOML
== ===================== =================

.. [#use-yaml]
   YAML format is supported only if you have installed secrets.env with pip extra ``[yaml]``.


Layouts
-------

Typically, the configuration file should contain ``source`` section to specify the secret provider, and its connection parameters, and a ``secrets`` section to list the value(s) to be loaded:

.. tabs::

   .. code-tab:: yaml

      source:
        type: vault
        url: https://example.com/
        auth: oidc

      secrets:
        VAR: "secret/default#example"

   .. code-tab:: toml

      [source]
      type = "vault"
      url = "https://example.com/"
      auth = "oidc"

      [secrets]
      VAR = "secret/default#example"

   .. code-tab:: json

      {
        "source": {
          "type": "vault",
          "url": "https://example.com/",
          "auth": "oidc"
        },
        "secrets": {
          "VAR": "secret/default#example"
        }
      }

.. note::

   This app can also read configurations from ``pyproject.toml`` file using the `PEP-518`_ format.
   To use this format, you need to use the template in TOML format and add the prefix ``tool.secrets-env`` to each section.
   For example, change ``[secrets]`` to ``[tool.secrets-env.secrets]``.

   .. _PEP-518: https://www.python.org/dev/peps/pep-0518/


Source
++++++

Source section specifies secret provider information.

Since this app uses "vault" as the default provider, the ``type`` field is not required but has been included for the sake of clarity and readability.

In addition, having more than one provider is also possible by modifying the "source" table to a list and giving each provider a unique ``name``:

.. tabs::

   .. code-tab:: yaml

      source:
        - name: vault-1
          url: https://vault-1.example.com/
          auth:
            method: okta
            username: user@example.com

        - name: vault-2
          url: https://vault-2.example.com/
          auth: oidc

   .. code-tab:: toml

      [[source]]
      name = "vault-1"
      url = "https://vault-1.example.com/"
      auth = {method = "okta", username = "user@example.com"}

      [[source]]
      name = "vault-2"
      url = "https://vault-2.example.com/"
      auth = "oidc"

   .. code-tab:: json

      {
        "source": [
          {
            "name": "vault-1",
            "url": "https://vault-1.example.com/",
            "auth": {
              "method": "okta",
              "username": "user@example.com"
            }
          },
          {
            "name": "vault-2",
            "url": "https://vault-2.example.com/",
            "auth": "oidc"
          }
        ]
      }


Secrets
+++++++

The "secrets" section lists key-value pairs where the keys correspond to the environment variable names in which the values will be stored.
The specific format of the value depends on the secret provider being used.
For example, in the case of Vault, the value could be either a string in the format of ``path#field``, or a table that includes the ``path`` and ``field`` fields.

If multiple providers are installed, you must provide the source name for each of them:

.. tabs::

   .. code-tab:: yaml

      secrets:
        VAR1:
          provider: vault-1
          path: secret/default
          field: example

   .. code-tab:: toml

      [secrets]
      VAR1 = {provider = "vault-1", path = "secret/default", field = "example"}

   .. code-tab:: json

      {
        "secrets": {
          "VAR1": {
            "provider": "vault-1",
            "path": "secret/default",
            "field": "example"
          }
        }
      }


Providers
---------

As of now, we have only a single provider.
For information on how to use it and its specifications, please refer to the following links.

.. toctree::
   :maxdepth: 2

   provider/vault

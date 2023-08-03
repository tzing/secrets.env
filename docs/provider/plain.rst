Plain Text Provider
===================

Plain text provider returns text that is copied directly from the configuration file.

In other words, this provider can be used as an alternative to an ``.env`` loader, which is useful for putting all environment variables in a single configuration file.
However, if you only need an ``.env`` loader, please refer to other more mature solutions, such as `python-dotenv`_.

type
   ``plain``

.. _python-dotenv: https://github.com/theskumar/python-dotenv

Configuration template
----------------------

.. note::

   These templates use :ref:`multiple sources config` format.

.. tabs::

   .. code-tab:: toml

      [[source]]
      name = "text"
      type = "plain"

      [secrets]
      FOO = { source = "text", value = "bar" }

   .. code-tab:: yaml

      source:
      - name: text
        type: plain

      secrets:
        FOO:
          source: text
          value: bar

   .. code-tab:: json

      {
        "source": [
          {
            "name": "text",
            "type": "plain"
          }
        ],
        "secrets": {
          "FOO": {
            "source": "text",
            "value": "bar"
          }
        }
      }

   .. code-tab:: toml pyproject.toml

      [[tool.secrets-env.source]]
      name = "text"
      type = "plain"

      [tool.secrets-env.secrets]
      FOO = { source = "text", value = "bar" }


Source section
--------------

Simply set ``type`` to ``plain``. No additional parameters are used by this provider.

Values
------

Values should be placed in ``value`` field, or a string could be used directly when used as the primary provider.

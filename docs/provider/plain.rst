Plain Text Provider
===================

The Plain Text provider directly transfers values from the configuration file to the environment variables.
Essentially functioning like an ``.env`` loader, it's ideal for configuring all environment variables from a single file.

However, if you solely require an ``.env`` loader, consider exploring simpler solutions like `python-dotenv`_.

.. _python-dotenv: https://saurabh-kumar.com/python-dotenv/

Configuration layout
--------------------

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         name = "typewriter"
         type = "plain"

         [[secrets]]
         name = "FOO"
         source = "typewriter"
         value = "baz"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - name: typewriter
             type: plain

         secrets:
           - name: FOO
             source: typewriter
             value: bar

   .. tab-item:: json

      .. code-block:: json

         {
           "sources": [
             {
               "name": "typewriter",
               "type": "plain"
             }
           ],
           "secrets": [
             {
               "name": "FOO",
               "source": "typewriter",
               "value": "bar"
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         name = "typewriter"
         type = "plain"

         [[tool.secrets-env.secrets]]
         name = "FOO"
         source = "typewriter"
         value = "baz"


Source section
--------------

Simply set ``type`` to ``plain``. No additional parameters are used by this provider.

Secrets section
---------------

Values should be placed in ``value`` field, or a string could be used directly when used in simplified mode:

.. tab-set::

   .. tab-item:: toml :bdg:`simplified`
      :sync: toml

      .. code-block:: toml

          [sources]
          type = "plain"

          [secrets]
          FOO = "baz"

   .. tab-item:: yaml :bdg:`simplified`
      :sync: yaml

      .. code-block:: yaml

          sources:
            type: plain

          secrets:
            FOO: bar

.. caution::

   This provider is still in the experimental stage and may change in the future.

1Password CLI provider
======================

Read values from 1Password using the `op`_ command.

.. _op: https://developer.1password.com/docs/cli

Source type
   ``1password:op``

.. important::

   To utilize this provider, verify that the ``op`` command is installed and properly configured.

   Importantly, you need to enable the *Integrate with 1Password CLI* option in the 1Password Desktop app.
   For additional information, refer to the `official installation guide`_.

   .. _official installation guide: https://developer.1password.com/docs/cli/get-started

Configuration layout
--------------------

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         type = "1password:op"
         name = "op"

         [[secrets]]
         name = "WP_USER"
         source = "op"
         ref = "Wordpress"
         field = "password"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - type: 1password:op
             name: op

         secrets:
           - name: WP_USER
             source: op
             ref: Wordpress
             field: password

   .. tab-item:: json

      .. code-block:: json

         {
           "sources": [
             {
               "type": "1password:op",
               "name": "op"
             }
           ],
           "secrets": [
             {
               "name": "WP_USER",
               "source": "op",
               "ref": "Wordpress",
               "field": "password"
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         type = "1password:op"
         name = "op"

         [[tool.secrets-env.secrets]]
         name = "WP_USER"
         source = "op"
         ref = "Wordpress"
         field = "password"

Source section
--------------

.. tip::

   All source configuration are optional.

``bin``
^^^^^^^

Defines the path to the ``op`` command. By default, the system path is used.

Secrets section
---------------

The configuration in the ``secrets`` section defines the item and field to retrieve from 1Password.

.. note::

   A field name followed by a bookmark icon (:octicon:`bookmark`) indicates that it is a required parameter.

``ref`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The item ID or name in 1Password.

The value can be either the item's UUID or its title, and it is case-insensitive.

``field`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Field to retrieve from the item.

Both field names and field UUIDs are supported, and they are case-insensitive.


Simplified layout
-----------------

This provider accepts 1Password's `secret reference`_ as the simplified representation.

.. _secret reference: https://developer.1password.com/docs/cli/secret-reference-syntax/

.. tab-set::

   .. tab-item:: toml :bdg:`simplified`
      :sync: toml

      .. code-block:: toml

         [sources]
         type = "1password:op"

         [secrets]
         WP_USER = "op://Private/2yysndf2j5bhracufqakofhb3e/email"

   .. tab-item:: yaml :bdg:`simplified`
      :sync: yaml

      .. code-block:: yaml

         sources:
           - type: 1password:op

         secrets:
           WP_USER: "op://Private/2yysndf2j5bhracufqakofhb3e/email"

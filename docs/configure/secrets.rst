Secret values
-------------

The ``secrets`` section is a required section which must be written in the config file and no alternative source supported.

.. tabs::

   .. code-tab:: yaml

      secrets:
        VAR1:
         path: kv/default
         key: example.to.value

        VAR2: "kv/default#example.to.value"  # shortcut: path#key

   .. code-tab:: toml

      [secrets]
      VAR1 = {path = "kv/default", key = "example.to.value"}
      VAR2 = "kv/default#example.to.value"  # shortcut: path#key

name
   The name on left side (``VAR1``, ``VAR2``) would be the destination environment variable name after the secrets is loaded.

path
   Path to read secret from vault.

key
   Key is the field name to identify which value to extract. For nested structure, join the keys with dots.

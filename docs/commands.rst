Commands
--------

Secrets.env includes a command-line interface.
To access assistance from the command line, simply run ``secrets.env --help`` to view the full list of available commands.


.. click:: secrets_env.console.commands.completion:completion
   :prog: secrets.env completion

.. click:: secrets_env.console.commands.config:group
   :prog: secrets.env config
   :nested: full

.. _cmd.keyring:

.. click:: secrets_env.console.commands.keyring:group
   :prog: secrets.env keyring
   :nested: full

.. click:: secrets_env.console.commands.run:run
   :prog: secrets.env run

.. click:: secrets_env.console.commands.shell:shell
   :prog: secrets.env shell

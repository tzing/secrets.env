Commands
--------

Secrets.env includes a command-line interface.
To access assistance from the command line, simply run ``secrets.env --help`` to view the full list of available commands.


.. click:: secrets_env.console.commands.completion:completion
   :prog: secrets.env completion

.. click:: secrets_env.console.commands.run:run
   :prog: secrets.env run

.. _cmd.set:

.. click:: secrets_env.console.commands.set:group_set
   :prog: secrets.env set
   :nested: full

.. _cmd.shell:

.. click:: secrets_env.console.commands.shell:shell
   :prog: secrets.env shell

.. _cmd.show:

.. click:: secrets_env.console.commands.show:show
   :prog: secrets.env show

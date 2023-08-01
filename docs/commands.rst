Commands
--------

Secrets.env comes with command line interface for you.

To get help from the command-line, call ``secrets.env`` to read the complete command list.g

.. code-block:: bash

   secrets.env [OPTIONS] COMMAND [ARGS]...


completion
==========

This command prints shell completion script for the program.

You can enable completion by running following command in your terminal:

.. code-block:: bash

   eval "$(secrets.env completion)"


run
===

This command loads secrets into environment variable then run the command.

``-C, --config FILE``
   Specify an alternative configuration file.

``--strict / --no-strict``
   Use strict mode. Stop run when not all of the values loaded.  [default: strict]

``-q, --quiet``
   Silent mode. Don't show output until error.

``-v, --verbose``
   Increase output verbosity.


version
=======

This command show current version.

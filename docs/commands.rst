Commands
--------

Secrets.env includes a command-line interface.
To access assistance from the command line, simply run ``secrets.env --help`` to view the full list of available commands.


``completion``
==============

This command prints shell completion script for the program.

You can enable completion by running following command in your terminal:

.. code-block:: bash

   eval "$(secrets.env completion)"


``keyring del``
===============

Remove a credential from system keyring.

*Usage:*

.. code-block:: bash

   secrets.env keyring del HOST TARGET

*Arguments:*

``HOST``
   The hostname/url to the vault that uses this credential.

``TARGET``
   The target credential name. It could be ``token`` for auth token, or the username for login.


.. _cmd.keyring.set:

``keyring set``
===============

Command to store credential in system keyring.

*Usage:*

.. code-block:: bash

   secrets.env keyring set HOST TARGET [VALUE]

*Arguments:*

``HOST``
   The hostname/url to the vault that uses this credential.

``TARGET``
   The target credential name. It could be ``token`` for auth token, or the username for login.

``VALUE``
   The credential value. This app will prompt for input when it is not passed as an argument.


``keyring status``
==================

Command to check if keyring is available.

*Usage:*

.. code-block:: bash

    secrets.env keyring status


``run``
=======

This command loads secrets into environment variable and run the command.

*Usage:*

.. code-block:: bash

   secrets.env run [OPTIONS] -- CMD [ARGS]...

*Options:*

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

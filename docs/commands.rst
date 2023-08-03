Commands
--------

Secrets.env comes with command line interface.
To get help from the command-line, call ``secrets.env`` to read the complete command list.

**Usage**

.. code-block:: bash

   secrets.env [OPTIONS] COMMAND [ARGS]...


completion
==========

This command prints shell completion script for the program.

You can enable completion by running following command in your terminal:

.. code-block:: bash

   eval "$(secrets.env completion)"


.. _command-keyring:

keyring
=======

Manage credential using system keyring service.

keyring del
+++++++++++

Remove a credential from system keyring.

**Usage**

.. code-block:: bash

   secrets.env keyring del HOST TARGET

**Arguments**

``HOST``
   The hostname/url to the vault that uses this credential.

``TARGET``
   The target credential name. It could be ``token`` for auth token, or the username for login.

keyring set
+++++++++++

Command to store credential in system keyring.

.. code-block:: bash

   secrets.env keyring set HOST TARGET [VALUE]

**Arguments**

``HOST``
   The hostname/url to the vault that uses this credential.

``TARGET``
   The target credential name. It could be ``token`` for auth token, or the username for login.

``VALUE``
   The credential value. This app will prompt for input when it is not passed as an argument.

keyring status
++++++++++++++

Command to check if keyring is available.

**Usage**

.. code-block:: bash

    secrets.env keyring status


run
===

This command loads secrets into environment variable then run the command.

**Usage**

.. code-block:: bash

   secrets.env run [OPTIONS] -- CMD [ARGS]...

**Options**

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

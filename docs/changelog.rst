Changelog
---------

1.0.2
=====

:Date: 2024-08-23

Enhancements
++++++++++++

* Prevent saving Vault token to token helper for root user.

* Use the provider type name as default instance name.

  .. code-block:: yaml

     sources:
       # This source will be named as `plain`
       - type: plain

     secrets:
       - name: DEMO
         source: plain
         value: Hello, world!

* Set the provider as default when only one is installed.

  This simplifies the configuration file when only one provider is installed:

  .. code-block:: yaml

     sources:
       - name: ExampleSource
         type: plain

     secrets:
       # This secret will be fetched from `ExampleSource`
       - name: DEMO
         value: Hello, world!

Docs
++++

* Move the changelog to Sphinx documentation


1.0.1
=====

:Date: 2024-08-13

Re-release of 1.0.0 with updated classifiers.


1.0.0
=====

:Date: 2024-08-13

Added
+++++

* Introduce :ref:`cmd.show` command to parses and displays the configuration file's contents without executing any commands.

  This command helps users understand how secrets.env interprets the configuration file and identifies critical errors.

* Set environment variable :envvar:`SECRETS_ENV_ACTIVE` when secrets.env is active.
  And use this variable to prevent recursive execution of secrets.env.

* Add command :ref:`cmd.shell` that spawns a shell with the environment variables loaded by secrets.env.

* Add command :ref:`cmd.set` to store username and password in user space.

* Add :ref:`vault.meth.kubernetes` method to :doc:`provider/vault`,
  allowing user to authenticate with Vault using a Kubernetes service account token.

Changed
+++++++

* Command group ``keyring`` is merged into :ref:`set password <cmd.set>` command
* Use `shellingham <https://github.com/sarugaku/shellingham>`_ to detect the shell type.
* Refactor ``secrets_env.console`` module.


0.29.1
======

:Date: 2024-05-15

Added
+++++

* :doc:`provider/vault` now integrated with Vault's `token helper <https://www.vaultproject.io/docs/commands/token-helper>`_.

Changed
+++++++

* Shifted some alerts to the :py:mod:`warnings` module to minimize the warning notifications displayed to the user.


0.29.0
======

:Date: 2024-05-07

Added
+++++

* The secrets section in the config file now supports list as well as dictionary.

  .. code-block:: yaml

     secrets:
       - name: secret1
         source: vault
         path: secret/sample
         field: token
       - name: secret2
         source: plaintext
         value: example

Changed
+++++++

* The keyword for Vault's :ref:`vault.meth.userpass` got changed to ``userpass``.

  This change is to align the naming with the Vault's auth method.

* Vault's :ref:`vault.meth.token` auth adapter no longer reads token from keyring.

  Vault only provide short-lived tokens, so it is not practical to store them in keyring.

* Deprecate the ``teleport+vault`` keyword.

  The keyword was used to configure the Teleport-integrated Vault secret provider.
  It is now covered by :ref:`vault.teleport` config.

* Command ``keyring set`` now accepts password from stdin.

* Refactor the configuration parsers.
  Internally switch from using :py:class:`dict` to :py:mod:`pydantic` models.

* Refactor layout of the adapter classes to make the code more extensible.

Docs
++++

* Revise the documentation to ensure consistency across different providers.


Prior to 0.29
=============

Changes made prior to version 0.29 of secrets.env are not documented.

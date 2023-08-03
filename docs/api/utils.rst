Utilities
=========

secrets_env.utils module
------------------------

.. automodule:: secrets_env.utils

   Input
   +++++

   .. autofunction:: get_bool_from_env_var
   .. autofunction:: get_env_var
   .. autofunction:: prompt

   Keyring integration
   +++++++++++++++++++

   .. autofunction:: create_keyring_login_key
   .. autofunction:: create_keyring_token_key
   .. autofunction:: read_keyring

   Text formating
   ++++++++++++++

   .. autofunction:: strip_ansi

   Type checking
   +++++++++++++

   .. autofunction:: ensure_type
   .. autofunction:: ensure_dict
   .. autofunction:: ensure_path
   .. autofunction:: ensure_str

secrets_env.server module
-------------------------

.. automodule:: secrets_env.server

   .. autofunction:: start_server

   .. autoclass:: HTTPRequestHandler

      .. autoattribute:: server
      .. automethod:: route

      .. automethod:: response_html
      .. automethod:: response_error

   .. autoclass:: ThreadingHTTPServer

      .. autoattribute:: context
      .. autoattribute:: ready
      .. autoproperty:: server_uri

      .. automethod:: create

secrets_env.subprocess module
-----------------------------

.. automodule:: secrets_env.subprocess

   .. autoclass:: Run

      .. autoproperty:: return_code
      .. autoproperty:: stdout
      .. autoproperty:: stderr

      .. automethod:: wait
      .. automethod:: iter_any_output

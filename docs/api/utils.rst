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
   .. autofunction:: read_keyring

   Logging
   +++++++

   .. autofunction:: get_httpx_error_reason
   .. autofunction:: log_httpx_response

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

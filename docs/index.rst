Secrets.env
===========

.. attention::

   I'm currently reworking the documentation. Many pages might be incomplete.

   Please refer to the `stable version <https://secrets-env.readthedocs.io/en/stable/>`_ or the `source code <https://github.com/tzing/secrets.env>`_ for more details.

Secrets.env connects the credential store to your development environment.

Safeguard your sensitive data by securely retrieving and injecting credentials into your environment variables.
Just like a ``.env`` loader, but without landing credentials on disk.

.. image:: imgs/screenshot.png

While security remains paramount, it shouldn't hinder your progress. While we value secret management services, obtaining secrets for local development can be cumbersome.

Enter our solution: designed to seamlessly integrate secrets into your development workflow without storing data on disk. Easily replicate environments and mitigate the risk of inadvertently exposing secrets.


User guide
----------

.. toctree::
   :maxdepth: 1

   introduction
   commands
   configurations
   addon/index

.. toctree::
   :caption: Links
   :hidden:

   GitHub <https://github.com/tzing/secrets.env/>
   PyPI <https://pypi.org/project/secrets-env/>

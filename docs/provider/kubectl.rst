.. caution::

   This provider is still in the experimental stage and may change in the future.

Kubectl Provider
================

Fetches values from Kubernetes using the `kubectl`_ command.

.. _kubectl: https://kubernetes.io/docs/reference/kubectl/

Source type
   ``kubernetes:kubectl``

.. important::

   To use this provider, ensure that the ``kubectl`` command is installed and configured.
   Additionally, the user must have the required permissions to access the requested resources.


Configuration layout
--------------------

.. tab-set::

   .. tab-item:: toml
      :sync: toml

      .. code-block:: toml

         [[sources]]
         type = "kubernetes:kubectl"
         name = "kube"

         [[secrets]]
         name = "FOO"
         source = "kube"
         ref = "default/demo-secret"
         key = "foo"

   .. tab-item:: yaml
      :sync: yaml

      .. code-block:: yaml

         sources:
           - type: kubernetes:kubectl
             name: kube

         secrets:
           - name: FOO
             source: kube
             ref: default/demo-secret
             key: foo

   .. tab-item:: json

      .. code-block:: json

         {
           "sources": [
             {
               "type": "kubernetes:kubectl",
               "name": "kube"
             }
           ],
           "secrets": [
             {
               "name": "FOO",
               "source": "kube",
               "ref": "default/demo-secret",
               "key": "foo"
             }
           ]
         }

   .. tab-item:: pyproject.toml

      .. code-block:: toml

         [[tool.secrets-env.sources]]
         type = "kubernetes:kubectl"
         name = "kube"

         [[tool.secrets-env.secrets]]
         name = "FOO"
         source = "kube"
         ref = "default/demo-secret"
         key = "foo"


Source section
--------------

.. tip::

   All source configuration are optional.

   The provider will invoke the ``kubectl`` command and leverage the default configuration if not provided.

``bin``
^^^^^^^

Specifies the path to the kubectl binary.
If not provided, the provider will search for it in the ``$PATH``.

``config``
^^^^^^^^^^

Defines the path to the `kubeconfig`_ file.
If omitted, the default kubeconfig will be utilized. Alternatively, this can be configured using the :envvar:`KUBECONFIG` environment variable.

.. _kubeconfig: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/

``context``
^^^^^^^^^^^

Specifies the Kubernetes `context`_ to use.
If not provided, the current context will be used.

.. _context: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#context


Secrets section
---------------

The configurations within the ``secrets`` section determine the object and the field to be read.

.. note::

   A field name followed by a bookmark icon (:octicon:`bookmark`) indicates that it is a required parameter.

``ref`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Namespace`_ and `object name`_ in the format of ``namespace/object-name``.

.. _namespace: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
.. _object name: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/

``key`` :octicon:`bookmark`
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Key to read from the object.

``kind``
^^^^^^^^

Specifies the kind of object to read. This field must be one of the following values, case-insensitive:

- ``Secret`` (default): Read confidential values from a `Secret`_ object.
- ``ConfigMap``: Read value from a `ConfigMap`_ object.

.. _secret: https://kubernetes.io/docs/concepts/configuration/secret/
.. _configmap: https://kubernetes.io/docs/concepts/configuration/configmap/


Simplified layout
-----------------

This provider accepts strings in the format ``namespace/secret-name#key`` as the simplified representation.

On using the simplified layout, the provider only reads the secrets.

.. tab-set::

   .. tab-item:: toml :bdg:`simplified`
      :sync: toml

      .. code-block:: toml

         [sources]
         type = "kubernetes:kubectl"

         [secrets]
         USERNAME = "default/demo-secret#username"
         PASSWORD = { ref = "default/demo-secret", key = "password" }

   .. tab-item:: yaml :bdg:`simplified`
      :sync: yaml

      .. code-block:: yaml

         source:
           type: kubernetes:kubectl

         secrets:
           USERNAME: default/demo-secret#username
           PASSWORD:
             ref: default/demo-secret
             key: password

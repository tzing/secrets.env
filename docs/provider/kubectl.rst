Kubectl Provider
================

This provider reads the Kubernetes secrets using the ``kubectl`` command.

.. important::

   To use this provider, you must have the ``kubectl`` command installed and configured.


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

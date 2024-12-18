package policy

test_allowed_configmaps {
  testcase = {
    "parameters": {
      "exclude_namespaces": [],
      "exclude_label_key": "",
      "exclude_label_value": "",
      "configmaps": ["allowed-configmap"]
    },
    "review": {
      "object": {
        "apiVersion": "v1",
        "kind": "HelmRelease",
        "metadata": {
          "name": "test-helm-release",
          "namespace": "default"
        },
        "spec": {
          "valuesFrom": [
            {
              "kind": "ConfigMap",
              "name": "allowed-configmap"
            }
          ]
        }
      }
    }
  }

  count(violation) == 0 with input as testcase
}

test_unallowed_configmaps {
  testcase = {
    "parameters": {
      "exclude_namespaces": [],
      "exclude_label_key": "",
      "exclude_label_value": "",
      "configmaps": ["allowed-configmap"]
    },
    "review": {
      "object": {
        "apiVersion": "v1",
        "kind": "HelmRelease",
        "metadata": {
          "name": "test-helm-release",
          "namespace": "default"
        },
        "spec": {
          "valuesFrom": [
            {
              "kind": "ConfigMap",
              "name": "unallowed-configmap"
            }
          ]
        }
      }
    }
  }

  count(violation) == 1 with input as testcase
}

test_exclude_namespace_configmaps {
  testcase = {
    "parameters": {
      "exclude_namespaces": ["excluded-namespace"],
      "exclude_label_key": "",
      "exclude_label_value": "",
      "configmaps": ["allowed-configmap"]
    },
    "review": {
      "object": {
        "apiVersion": "v1",
        "kind": "HelmRelease",
        "metadata": {
          "name": "excluded-helm-release",
          "namespace": "excluded-namespace"
        },
        "spec": {
          "valuesFrom": [
            {
              "kind": "ConfigMap",
              "name": "unallowed-configmap"
            }
          ]
        }
      }
    }
  }

  count(violation) == 0 with input as testcase
}

test_exclude_label_configmaps {
  testcase = {
    "parameters": {
      "exclude_namespaces": [],
      "exclude_label_key": "exclude-me",
      "exclude_label_value": "true",
      "configmaps": ["allowed-configmap"]
    },
    "review": {
      "object": {
        "apiVersion": "v1",
        "kind": "HelmRelease",
        "metadata": {
          "name": "test-helm-release",
          "namespace": "default",
          "labels": {
            "exclude-me": "true"
          }
        },
        "spec": {
          "valuesFrom": [
            {
              "kind": "ConfigMap",
              "name": "unallowed-configmap"
            }
          ]
        }
      }
    }
  }

  count(violation) == 0 with input as testcase
}

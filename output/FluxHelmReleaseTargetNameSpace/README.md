# Helm Release Target Namespace

HelmRelease targetNamespace must be one of the allowed targetNamespace list.

Set the targetNamespace of the HelmRelease to one of the allowed namespaces.

# Settings

Rego parameters:
```yaml
  settings:
    parameters:
      - name: target_namespaces
        type: array
        required: true
        value:
      - name: exclude_namespaces
        type: array
        required: false
        value: []
      - name: exclude_label_key
        type: string
        required: false
        value:
      - name: exclude_label_value
        type: string
        required: false
        value:
```

# Resources
Policy applies to resources kinds:
`HelmRelease`
# Rbac Prohibit Wildcard On Secrets

This Policy will violate if any RBAC ClusterRoles or Roles are designated with 'wildcard' verb on 'secrets' resource.


When deploying RBAC roles, ensure the resource and verb combination you choose are allowed by the Policy. 
```
rules:
- resources: <resources>
  verbs: <verb>
```

https://kubernetes.io/docs/reference/access-authn-authz/rbac/


# Settings

Rego parameters:
```yaml
  settings:
    parameters:
      - name: resource
        type: string
        required: true
        value: "secrets"
      - name: verb
        type: string
        required: true
        value: "*"
      - name: exclude_label_key
        type: string
        required: false
        value: ""
      - name: exclude_label_value
        type: string
        required: false
        value: ""
```

# Resources
Policy applies to resources kinds:
`Role`, `ClusterRole`
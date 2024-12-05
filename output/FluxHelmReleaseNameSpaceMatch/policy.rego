package policy

import future.keywords.in

exclude_namespaces := input.parameters.exclude_namespaces
exclude_label_key := input.parameters.exclude_label_key
exclude_label_value := input.parameters.exclude_label_value

violation[result] {
    isExcludedNamespace == false
    not exclude_label_value == controller_input.metadata.labels[exclude_label_key]
    storage_namespace := controller_spec.storageNamespace
    target_namespace := controller_spec.targetNamespace
    storage_namespace != target_namespace
    not exclude_label_value == controller_input.metadata.labels[exclude_label_key]
    result = {
        "issue_detected": true,
        "msg": sprintf("The HelmRelease '%s' storageNamespace and targetNamespace must match; found storageNamespace '%s' and targetNamespace '%s'", [controller_input.metadata.name, storage_namespace, target_namespace]),
        "violating_key": "spec.targetNamespace"
    }
}

# Controller input
controller_input = input.review.object

# controller_container acts as an iterator to get containers from the template
controller_spec = controller_input.spec {
    controller_input.kind == "HelmRelease"
}

contains_kind(kind, kinds) {
    kinds[_] = kind
}

isExcludedNamespace = true {
    controller_input.metadata.namespace
    controller_input.metadata.namespace in exclude_namespaces
} else = false

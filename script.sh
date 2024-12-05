#!/usr/bin/env bash
set -eEuo pipefail

# ==================================================================================================
# Logging & Functions & Traps

yq() { command yq -e "$@"; }
jq() { command jq -e "$@"; }

exec 3>&1     # keep logs on stdout after redirection
: ${OUTPUT:=} # don't print twice if output=stdout
log  () { printf -- "$(date +%R) \e[${1}m${*:2}\e[0m\n" | tee -a ${OUTPUT/\/dev\/stdout} >&3; }
step () { log 32 "${*}" $(basename "${BASH_SOURCE[1]/${BASH_SOURCE}}" | sed 's/.\+/[&]/'); } # print test module
info () { log 0  "  ${*}"; }
warn () { log 33 "  ${*}"; }
error() { log 31 "  ${*}"; }

trap_exit() {
    status=$?
    if [ $status -ne 0 ]; then
        tail -20 "$OUTPUT" | sed -r -e 's:\x1b\[[0-9;]*[mK]::g' -e 's/^/> /' >&3
        exit $status
    fi
}

trap 'echo "Error on ${BASH_SOURCE}:${LINENO} $(sed -n "${LINENO} s/^\s*//p" ${BASH_SOURCE})"' ERR
trap 'trap_exit' EXIT

# ==================================================================================================
# Variables & Functions

: ${BASEDIR:=$PWD}
: ${DATADIR:=$BASEDIR/data}
exec &>> ${OUTPUT:=$BASEDIR/script.log}

# Use parameter as policy name or target all policies
POLICIES="${1:-$(cat $DATADIR/policies.txt)}"

do_readme() {
    yq '"# " + .spec.name' "$INDIR/policy.yaml"
    echo

    yq '.spec.description' "$INDIR/policy.yaml"
    echo
    yq '.spec.how_to_solve' "$INDIR/policy.yaml"
    echo

    echo "# Settings"
    echo
    echo "Rego parameters:"
    echo

    yq '{"settings": .spec.parameters}' "$INDIR/policy.yaml"
}


# Pod Deployment Job ReplicationController ReplicaSet DaemonSet StatefulSet CronJob Bucket HelmChart HelmRelease HelmRepository Namespace NetworkPolicy PersistentVolume ClusterRoleBinding Role ClusterRole ServiceAccount Service

# rules:
#   - apiGroups: ""
#     apiVersions: "v1"
#     resources: ["pods", "namespaces", "services", "serviceaccounts", "persistentvolumes", "replicationcontrollers"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "apps"
#     apiVersions: "v1"
#     resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "batch"
#     apiVersions: "v1"
#     resources: ["jobs", "cronjobs"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "networking.k8s.io"
#     apiVersions: "v1"
#     resources: ["networkpolicies"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "helm.toolkit.fluxcd.io"
#     apiVersions: "v2"
#     resources: ["helmreleases"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "source.toolkit.fluxcd.io"
#     apiVersions: "v1"
#     resources: ["buckets", "helmcharts", "helmrepositories"]
#     operations: ["CREATE", "UPDATE"]
#   - apiGroups: "rbac.authorization.k8s.io"
#     apiVersions: "v1"
#     resources: ["clusterrolebindings", "roles", "clusterroles"]
#     operations: ["CREATE", "UPDATE"]

# Get crds for flux (helmreleases, buckets, helmcharts, helmrepositories)
# kubectl apply -f https://github.com/fluxcd/flux2/releases/latest/download/install.yaml

# pods                    v1                            Pod
# namespaces              v1                            Namespace
# services                v1                            Service
# serviceaccounts         v1                            ServiceAccount
# persistentvolumes       v1                            PersistentVolume
# replicationcontrollers  v1                            ReplicationController
# deployments             apps/v1                       Deployment
# replicasets             apps/v1                       ReplicaSet
# daemonsets              apps/v1                       DaemonSet
# statefulsets            apps/v1                       StatefulSet
# jobs                    batch/v1                      Job
# cronjobs                batch/v1                      CronJob
# networkpolicies         networking.k8s.io/v1          NetworkPolicy
# helmreleases            helm.toolkit.fluxcd.io/v2     HelmRelease
# buckets                 source.toolkit.fluxcd.io/v1   Bucket
# helmcharts              source.toolkit.fluxcd.io/v1   HelmChart
# helmrepositories        source.toolkit.fluxcd.io/v1   HelmRepository
# clusterrolebindings     rbac.authorization.k8s.io/v1  ClusterRoleBinding
# roles                   rbac.authorization.k8s.io/v1  Role
# clusterroles            rbac.authorization.k8s.io/v1  ClusterRole


do_metadata() {
    yq '{"rules":
        # Define the target kinds from the input spec
        .spec.targets.kinds as $targetKinds |

        # Load the kinds mapping from the separate YAML file
        load("data/kinds-mapping.yaml").kinds_mapping as $kindMap |

        # Create an array of matched kinds
        [
            $targetKinds[] |
            select($kindMap[.]) |
            {"name": ., "details": $kindMap[.]}
        ] |

        # Group by API group
        group_by(.details.apiGroup) |

        # Transform each group
        map({
            "apiGroups": [.[0].details.apiGroup],
            "apiVersions": [.[0].details.apiVersion],
            "resources": [map(.details.resource)[]],
            "operations": ["CREATE", "UPDATE"]
        })}
    ' "$INDIR/policy.yaml"

    yq '{
        "mutating": false,
        "executionMode": "gatekeeper",
        "backgroundAudit": true
    }' "$INDIR/policy.yaml"

    yq '{"annotations": (
        {
        "io.kubewarden.policy.title": (.spec.id | sub("weave.policies."; "")),
        "io.artifacthub.displayName": .spec.name,
        "io.kubewarden.policy.description": .spec.description | from_yaml,
        "io.artifacthub.resources": .spec.targets.kinds | join(", "),
        "io.kubewarden.policy.author": "Kubewarden developers <cncf-kubewarden-maintainers@lists.cncf.io>",
        "io.kubewarden.policy.ociUrl": "ghcr.io/kubewarden/policies/" + (.spec.id | sub("weave.policies."; "")),
        "io.kubewarden.policy.url": "https://github.com/kubewarden/rego-policies",
        "io.kubewarden.policy.source": "https://github.com/kubewarden/rego-policies",
        "io.kubewarden.policy.license": "Apache-2.0",
        "io.kubewarden.policy.category": (.spec.category | sub("weave.categories."; "")),
        "io.kubewarden.policy.severity": .spec.severity
        } + (
        .spec.standards // [] | map({"key": "io.kubewarden.policy.standards." + (.id | sub("weave.standards."; "")), "value": (.controls | map(sub("weave.controls."; "")) | join(", "))}) | from_entries
        )
    )}' "$INDIR/policy.yaml"

    # io.artifacthub.keywords: compliance, SSH, containers

    # yq '.spec.standards | map({"io.kubewarden.policy.standards." + (.id |  sub("weave.standards.";"")): (.controls | map(sub("weave.controls."; "")) | join(", "))})' "$INDIR/policy.yaml"

    # yq 'with(
    # .spec.standards[];
    # {"io.kubewarden.policy.standards." + .id: (.controls | map(sub("weave.controls."; "")) | join(", "))}
    # ) | add' input.yaml

    # yq 'with(
    # .spec.standards[];
    # .id as $id |
    # {"("io.kubewarden.policy.standards." + ($id | split(".")[-1]))": (.controls | map(sub("weave.controls."; "")) | join(", "))}
    # ) | add' "$INDIR/policy.yaml"
}

# ==================================================================================================

# TODOs
# Use tags?
# tags: [pci-dss, cis-benchmark, mitre-attack, nist800-190, gdpr, default]


POLICIES="ControllerContainerBlockSSHPort"

for pol in $POLICIES; do
    INDIR="$BASEDIR/input/policies/$pol"
    OUTDIR="$BASEDIR/output/$pol"

    step "$pol"
    test -d "$INDIR" || { error "Policy not found: $pol"; exit 1; }
    mkdir -p "$OUTDIR"

    info "Compile readme"
    do_readme > "$OUTDIR/README.md"

    info "Compile metadata"
    do_metadata | tee "$OUTDIR/metadata.yml"
    # TODO: this replaces already set category, expected?
    if grep -w "$pol" "$INDIR/../../goodpractices/kubernetes/rbac/secrets/kustomization.yaml" > /dev/null; then
        yq -i '.annotations."io.kubewarden.policy.category" = "Best practices RBAC"' "$OUTDIR/metadata.yml"
    fi

    info "Adapt policy.rego"
    sed 's/^package weave.*/package policy/' "$INDIR/policy.rego" > "$OUTDIR/policy.rego"

    info "Use tests"
    cp -r "$INDIR/tests" "$OUTDIR/"
    cd "$OUTDIR/"; make tests; cd -

    info "Use makefile"
    cp "$DATADIR/Makefile" "$OUTDIR/"
    cd "$OUTDIR"
    VERSION=0.0.1 make artifacthub-pkg.yml
    make policy.wasm annotated-policy.wasm
    cd -

    info "Done."

done


#   Reuse our OPA Rego Makefile from disallow-service-loadbalander-policy. Should be
# adapted to run rego tests with opa from ./tests. Not all policies have a
# ./tests/policy_test.rego.
#  Compile a README.md from policy.yaml, by reusing the following fields in a template:
#  metadata.name with weave.policies prefix removed.
#  spec.name, description, how_to_solve, tags.
#  Compile a metadata.yml from policy.yaml, by reusing the following fields from the Weaveworks policy:
# - spec.id, without the prefix weave.policies, as annotations
# io.kubewarden.policy.title, io.kubewarden.policy.ociUrl:  ghcr.io/kubewarden/policies/<id>, io.kubewarden.policy.url: https://github.com/kubewarden/<id>.
# - io.kubewarden.policy.url and io.kubewarden.policy.source hardcoded to the Rego monorepo for these policies. (e.g: https://github.com/kubewarden/rego-policies).
# - spec.category as annotations io.kubewarden.policy.category, without prefix weave.category.
# - spec.severity as annotations io.kubewarden.policy.severity
# - spec.standards as annotation io.kubewarden.policy.standards, where each
# element in the controls array is a new annotation, and it is commented out until we evaluate further. The list of available standards are in ./standards (example).
# - spec.description as annotation io.kubewarden.policy.description
# - spec.targets into rules and the annotation io.artifacthub.resources by computing the list of resources. This translation is not trivial.
#  Adapt the policy.rego:
# Use the same package for all rego files, including tests (e.g: package policy).
#  Reuse ./tests/, which will get run by the make tests
#  artifacthub-pkg.yml following artifacthub docs. Generated by our Makefile.

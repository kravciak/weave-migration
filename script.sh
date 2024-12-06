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
    echo '```yaml'
    yq '{"settings": .spec.parameters}' "$INDIR/policy.yaml"
    echo '```'
    echo

    echo "# Tags"
    echo -n "Policy applies to following resources:"
    yq '.spec.targets.kinds | map("`" + . + "`") | join(", ")' "$INDIR/policy.yaml"

}

# Get crds for flux (helmreleases, buckets, helmcharts, helmrepositories, kustomizations, ...)
# kubectl apply -f https://github.com/fluxcd/flux2/releases/latest/download/install.yaml

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
            "apiGroups": [.[0].details.apiGroup] | . style="flow",
            "apiVersions": [.[0].details.apiVersion] | . style="flow",
            "resources": [map(.details.resource)[]] | . style="flow",
            "operations": ["CREATE", "UPDATE"] | . style="flow"
        })}
    ' "$INDIR/policy.yaml"

    yq '{
        "mutating": false,
        "executionMode": "gatekeeper",
        "backgroundAudit": true
    }' "$INDIR/policy.yaml"

    yq '{"annotations": (
        {
        "io.artifacthub.displayName": .spec.name,
        "io.artifacthub.keywords": .spec.tags | join(", "),
        "io.artifacthub.resources": .spec.targets.kinds | join(", "),
        "io.kubewarden.policy.title": (.spec.id | sub("weave.policies."; "")),
        "io.kubewarden.policy.description": .spec.description | from_yaml,
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
    sed -i '/io.kubewarden.policy.standards/ s/i/# i/' "$OUTDIR/metadata.yml" # Comment out standards
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

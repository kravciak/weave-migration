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

do_metadata() {
    # Fix hardcoded rules
    yq '{"rules": [{
        "apiGroups": [""],
        "apiVersions": ["v1"],
        "resources": ["*"],
        "operations": ["CREATE", "UPDATE", "DELETE"]
    }]}' "$INDIR/policy.yaml"

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
        .spec.standards | map({"key": "io.kubewarden.policy.standards." + (.id | sub("weave.standards."; "")), "value": (.controls | map(sub("weave.controls."; "")) | join(", "))}) | from_entries
        )
    )}' "$INDIR/policy.yaml"


    # yq '.spec.standards | map({"key": "io.kubewarden.policy.standards." + (.id | sub("weave.standards."; "")), "value": (.controls | map(sub("weave.controls."; "")) | join(", "))}) | from_entries' "$INDIR/policy.yaml"

    # yq '.spec.standards | map({"io.kubewarden.policy.standards." + (.id |  sub("weave.standards.";"")): (.controls | map(sub("weave.controls."; "")) | join(", "))})' "$INDIR/policy.yaml"

    # yq 'with(
    # .spec.standards[];
    # {"io.kubewarden.policy.standards." + .id: (.controls | map(sub("weave.controls."; "")) | join(", "))}
    # ) | add' input.yaml


    # yq '
    # to_entries |
    # map({
    #     "io.kubewarden.policy.standards.\(.key | split(".")[-1])":
    #     .value.controls |
    #     map(split(".")[-1]) |
    #     join(", ")
    # }) | reduce .[] as $item ({}; . * $item)' "$INDIR/policy.yaml"

    # yq 'with(
    # .spec.standards[];
    # .id as $id |
    # {"("io.kubewarden.policy.standards." + ($id | split(".")[-1]))": (.controls | map(sub("weave.controls."; "")) | join(", "))}
    # ) | add' "$INDIR/policy.yaml"

    # io.artifacthub.keywords: compliance, SSH, containers
    # yq '{"annotations": {"io.kubewarden.policy.standards": .spec.standards }}' "$INDIR/policy.yaml"
}

# ==================================================================================================

POLICIES="ControllerContainerBlockSSHPort"

for pol in $POLICIES; do
    INDIR="$BASEDIR/input/policies/$pol"
    OUTDIR="$BASEDIR/output/$pol"

    step "$pol"
    test -d "$INDIR" || { error "Policy not found: $pol"; exit 1; }
    mkdir -p "$OUTDIR"

    info "Insert makefile"
    cp "$DATADIR/Makefile" "$OUTDIR/"

    info "Compile readme"
    do_readme > "$OUTDIR/README.md"

    info "Compile metadata"
    do_metadata | tee "$OUTDIR/metadata.yml"

    info "Adapt policy.rego"
    sed 's/^package weave.*/package policy/' "$INDIR/policy.rego" > "$OUTDIR/policy.rego"

    info "Reuse tests"
    cp -r "$INDIR/tests" "$OUTDIR/"

    info "Done."

    # info "artifacthub-pkg.yml"
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

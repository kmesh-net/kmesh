#!/bin/bash

# NOTE: Kmesh e2e test framework is heavily inspired by istio integration 
# framework (https://github.com/istio/istio/tree/master/tests/integration),
# both in architecture and code.

# Exit immediately for non zero status
set -e

DEFAULT_KIND_IMAGE="gcr.io/istio-testing/kind-node:v1.30.0"

# Provision a kind clustr for testing.
function setup_kind_cluster() {
    local NAME="${1:-kmesh-testing}"
    local IMAGE="${2:-"${DEFAULT_KIND_IMAGE}"}"

    # Delete any previous KinD cluster.
    echo "Deleting previous KinD cluster with name=${NAME}"
    if ! (kind delete cluster --name="${NAME}" -v9) > /dev/null; then
        echo "No existing kind cluster with name ${NAME}. Continue..."
    fi

    # Create KinD cluster.
    if ! (kind create cluster --name="${NAME}" -v4 --retain --image "${IMAGE}"); then
        echo "Could not setup KinD environment. Something wrong with KinD setup. Exporting logs."
    fi    
}

while (( "$#" )); do
    case "$1" in
    --skip-setup)
      SKIP_SETUP=true
      shift
    ;;
    esac
done

if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_kind_cluster
fi

go test -tags=integ ./test/e2e/...

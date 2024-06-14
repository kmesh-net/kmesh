#!/bin/bash

# NOTE: Kmesh e2e test framework is heavily inspired by istio integration 
# framework (https://github.com/istio/istio/tree/master/tests/integration),
# both in architecture and code.

# Exit immediately for non zero status
set -e

DEFAULT_KIND_IMAGE="kindest/node:v1.30.0@sha256:047357ac0cfea04663786a612ba1eaba9702bef25227a794b52890dd8bcd692e"

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
    cat <<EOF | kind create cluster --name="${NAME}" -v4 --retain --image "${IMAGE}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF

    status=$?
    if [ $status -ne 0 ]; then
        echo "Could not setup KinD environment. Something wrong with KinD setup. Exporting logs."
    fi
}

export KIND_REGISTRY_NAME="kind-registry"
export KIND_REGISTRY_PORT="5000"
export KIND_REGISTRY="localhost:${KIND_REGISTRY_PORT}"
export HUB="${KIND_REGISTRY}"

# Provision a local docker registry, so KinD nodes could pull images from.
# https://kind.sigs.k8s.io/docs/user/local-registry/
function setup_kind_registry() {
    running="$(docker inspect -f '{{.State.Running}}' "${KIND_REGISTRY_NAME}" 2>/dev/null || true)"
    if [[ "${running}" != 'true' ]]; then
        docker run \
            -d --restart=always -p "${KIND_REGISTRY_PORT}:5000" --name "${KIND_REGISTRY_NAME}" \
            gcr.io/istio-testing/registry:2
        
        # Allow kind nodes to reach the registry
        docker network connect "kind" "${KIND_REGISTRY_NAME}"
    fi

    # Add the registry config to the nodes
    #
    # This is necessary because localhost resolves to loopback addresses that are network-namespace local.
    # In other words: localhost in the container is not localhost on the host.
    #
    # We want a consistent name that works from both ends, so we tell containerd to alias localhost:${reg_port}
    # to the registry container when pulling images
    REGISTRY_DIR="/etc/containerd/certs.d/localhost:${KIND_REGISTRY_PORT}"
    for node in $(kind get nodes); do
        docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
        cat << EOF | docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${KIND_REGISTRY_NAME}:5000"]
EOF
    done

    # Allow kind nodes to reach the registry
    # docker network connect "kind" "${KIND_REGISTRY_NAME}"

    # Document the local registry
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

function build_and_push_images() {
    make docker.push
}

while (( "$#" )); do
    case "$1" in
    --skip-setup)
      SKIP_SETUP=true
      shift
    ;;
    --skip-build)
      SKIP_BUILD=true
      shift
    ;;  
    esac
done

if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_kind_cluster
fi

if [[ -z "${SKIP_BUILD:-}" ]]; then
    setup_kind_registry

    build_and_push_images
fi

go test -v -tags=integ ./test/e2e/...

#!/bin/bash

# NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM ISTIO INTEGRATION
# FRAMEWORK(https://github.com/istio/istio/tree/master/tests/integration)
# AND ADAPTED FOR KMESH.

# Exit immediately for non zero status
set -e

DEFAULT_KIND_IMAGE="kindest/node:v1.30.0@sha256:047357ac0cfea04663786a612ba1eaba9702bef25227a794b52890dd8bcd692e"

ISTIO_VERSION=${ISTIO_VERSION:-"1.22.0"}

export KMESH_WAYPOINT_IMAGE=${KMESH_WAYPOINT_IMAGE:-"ghcr.io/kmesh-net/waypoint:latest"}

ROOT_DIR=$(git rev-parse --show-toplevel)

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

    if [[ -n "${IPV6:-}" ]]; then
        # Create IPv6 KinD cluster
        cat <<EOF | kind create cluster --name="${NAME}" -v4 --retain --image "${IMAGE}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  ipFamily: ipv6
nodes:
- role: control-plane
- role: worker
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
    else
        # Create default IPv4 KinD cluster
        cat <<EOF | kind create cluster --name="${NAME}" -v4 --retain --image "${IMAGE}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
    fi

    status=$?
    if [ $status -ne 0 ]; then
        echo "Could not setup KinD environment. Something wrong with KinD setup. Exporting logs."
    fi

    # Add the registry config to the nodes
    #
    # This is necessary because localhost resolves to loopback addresses that are network-namespace local.
    # In other words: localhost in the container is not localhost on the host.
    #
    # We want a consistent name that works from both ends, so we tell containerd to alias localhost:${reg_port}
    # to the registry container when pulling images
    REGISTRY_DIR="/etc/containerd/certs.d/localhost:${KIND_REGISTRY_PORT}"
    for node in $(kind get nodes --name="${NAME}"); do
        docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
        cat << EOF | docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${KIND_REGISTRY_NAME}:5000"]
EOF
    done

    # For KinD environment we need to mount bpf for each node, ref: https://github.com/kmesh-net/kmesh/issues/662
    for node in $(kind get nodes --name="${NAME}"); do
        docker exec "${node}" sh -c "mount -t bpf none /sys/fs/bpf"
    done

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

function setup_istio() {
    echo "install istio $ISTIO_VERSION"
    kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
        { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=v1.1.0" | kubectl apply -f -; }

    istioctl install --set profile=ambient --set meshConfig.accessLogFile="/dev/stdout" --skip-confirmation
}

function setup_kmesh() {
    helm install kmesh $ROOT_DIR/deploy/charts/kmesh-helm -n kmesh-system --create-namespace --set deploy.kmesh.image.repository=localhost:5000/kmesh

    # Wait for all Kmesh pods to be ready.
    while true; do
        pod_statuses=$(kubectl get pods -n kmesh-system -l app=kmesh -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.phase}{"\n"}{end}')

        running_pods=0
        total_pods=0

        while read -r pod_name pod_status; do
            total_pods=$((total_pods + 1))
            if [ "$pod_status" = "Running" ]; then
                running_pods=$((running_pods + 1))
            fi
        done <<< "$pod_statuses"

        if [ "$running_pods" -eq "$total_pods" ]; then
            echo "All pods of Kmesh daemon are in Running state."
            break
        fi

        echo "Waiting for pods of Kmesh daemon to enter Running state..."
        sleep 1
    done
}

export KIND_REGISTRY_NAME="kind-registry"
export KIND_REGISTRY_PORT="5000"
export KIND_REGISTRY="localhost:${KIND_REGISTRY_PORT}"

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
}

function build_and_push_images() {
    HUB="${KIND_REGISTRY}" TAG="latest" make docker.push
}

function install_dependencies() {
    # 1. Install kind.
    if ! which kind &> /dev/null
    then
        echo "install kind"

        go install sigs.k8s.io/kind@v0.23.0
    else
        echo "kind is already installed"
    fi
    
    # 2. Install helm.
    if ! which helm &> /dev/null
    then
        echo "install helm"

        curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3

        chmod 700 get_helm.sh

        ./get_helm.sh

        rm get_helm.sh
    else
        echo "helm is already installed"
    fi

    # 3. Install istioctl
    curl -L https://istio.io/downloadIstio | ISTIO_VERSION=${ISTIO_VERSION} TARGET_ARCH=x86_64 sh -

    cp istio-${ISTIO_VERSION}/bin/istioctl /usr/local/bin/

    rm -rf istio-${ISTIO_VERSION}
}

function cleanup_kind_cluster() {
    local NAME="${1:-kmesh-testing}"
    echo "Deleting KinD cluster with name=${NAME}"
    kind delete cluster --name="${NAME}"
    echo "KinD cluster ${NAME} cleaned up"
}

function cleanup_docker_registry() {
    echo "Stopping Docker registry named '${KIND_REGISTRY_NAME}'..."
    docker stop "${KIND_REGISTRY_NAME}" || echo "Failed to stop or no such registry '${KIND_REGISTRY_NAME}'."

    echo "Removing Docker registry named '${KIND_REGISTRY_NAME}'..."
    docker rm "${KIND_REGISTRY_NAME}" || echo "Failed to remove or no such registry '${KIND_REGISTRY_NAME}'."
}

PARAMS=()

while (( "$#" )); do
    case "$1" in
    --skip-install-dep)
      SKIP_INSTALL_DEPENDENCIES=true
      shift
    ;;
    --skip-setup)
      SKIP_SETUP=true
      shift
    ;;
    --skip-build)
      SKIP_BUILD=true
      shift
    ;;
    --only-run-tests)
      SKIP_INSTALL_DEPENDENCIES=true
      SKIP_SETUP=true
      SKIP_BUILD=true
      shift
    ;;
    --cluster)
      NAME="$2"
      if ! kind get clusters | grep -qw "$NAME"; then
        echo "Error: Cluster '$NAME' does not exist."
        exit 1
      fi
      shift 2
    ;;
    --ipv6)
      IPV6=true
      shift
    ;;
    --cleanup)
      CLEANUP_KIND=true
      CLEANUP_REGISTRY=true
      shift
    ;;
    *)
      PARAMS+=("$1")
      shift
    ;;
    esac
done

NAME="${NAME:-kmesh-testing}"

if [[ -z "${SKIP_INSTALL_DEPENDENCIES:-}" ]]; then
    install_dependencies
fi

if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_kind_cluster "$NAME"
fi

if [[ -z "${SKIP_BUILD:-}" ]]; then
    setup_kind_registry
    build_and_push_images
fi

kubectl config use-context "kind-$NAME"
echo "Running tests in cluster '$NAME'"


# make sure the Kmesh local image is ready.
if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_istio
    setup_kmesh
fi

cmd="go test -v -tags=integ $ROOT_DIR/test/e2e/... ${PARAMS[*]}"

bash -c "$cmd"

if [[ -n "${CLEANUP_KIND}" ]]; then
    cleanup_kind_cluster
fi

if [[ -n "${CLEANUP_REGISTRY}" ]]; then
    cleanup_docker_registry
fi
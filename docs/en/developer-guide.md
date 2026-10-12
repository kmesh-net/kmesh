# Developer Guide

## Table of Contents

- [Overview](#overview)
- [Development Environment](#development-environment)
  - [Supported Platforms](#supported-platforms)
  - [Required Tools](#required-tools)
  - [eBPF Development Dependencies](#ebpf-development-dependencies)
- [Repository Structure](#repository-structure)
- [Setting Up the Environment](#setting-up-the-environment)
- [Building Kmesh](#building-kmesh)
  - [Build from Source](#build-from-source)
  - [Build Docker Image](#build-docker-image)
  - [Clean Build Artifacts](#clean-build-artifacts)
- [Running Unit Tests](#running-unit-tests)
  - [Go Unit Tests](#go-unit-tests)
  - [eBPF Unit Tests](#ebpf-unit-tests)
- [Coding Conventions](#coding-conventions)
- [Running Kmesh Locally with Kind](#running-kmesh-locally-with-kind)
  - [Prerequisites](#prerequisites)
  - [Creating a Kind Cluster](#creating-a-kind-cluster)
  - [Deploying Kmesh on Kind](#deploying-kmesh-on-kind)
  - [Developing and Testing Code Changes in Kind](#developing-and-testing-code-changes-in-kind)
- [Debugging Tips](#debugging-tips)
- [Development Workflow](#development-workflow)

---

## Overview

This guide is intended for developers who want to build, test, and contribute to Kmesh. It covers
the tools required, how to compile the project, how to run tests, and how to iterate on code
changes locally using Kind.

If you are looking for deployment and usage instructions, see
[Compiling and Building Kmesh](kmesh_compile.md) and the
[Kmesh Quick Start](https://kmesh.net/en/docs/setup/quick-start/).

---

## Development Environment

### Supported Platforms

Kmesh relies on eBPF features that are only available on Linux. **Linux kernel >= 5.10 is required.**
You can check your kernel version with:

```bash
uname -r
```

CI for this project runs on **Ubuntu 22.04**. Other Linux distributions are supported; see
[Kmesh Support](kmesh_support.md) for the full compatibility matrix.

macOS and Windows are not supported for building or running Kmesh.

### Required Tools

| Tool | Minimum Version | Notes |
|---|---|---|
| Linux kernel | >= 5.10 | Required for eBPF features used by Kmesh |
| Go | 1.23+ | go.mod declares `go 1.24.2`; use 1.24.2+ for local development |
| Docker | any recent | Used to run the `kmesh-build` container |
| clang / clang++ | any recent | C and C++ compiler for eBPF programs |
| LLVM (llvm) | any recent | Required by clang for eBPF compilation |
| make | any | Build system |
| git | any | Version control |
| cmake | any | Used by `oncn-mda` sub-component |
| pkg-config | any | Used during linking |

#### Kubernetes and Istio versions

| Kmesh version | Kubernetes | Istio (Dual-Engine) | Istio (Kernel-Native) |
|---|---|---|---|
| main / latest | 1.26–1.31 | 1.23, 1.24, 1.25 | 1.23, 1.24, 1.25 |
| 1.1.x | 1.26–1.31 | 1.23, 1.24, 1.25 | 1.23, 1.24, 1.25 |

See [Kmesh Support](kmesh_support.md) for the complete version compatibility table.

### eBPF Development Dependencies

The build system installs these automatically via `make prepare-dev`, but understanding what
each tool does is helpful when diagnosing build failures.

| Tool | Purpose |
|---|---|
| clang | Compiles eBPF C programs to BPF bytecode |
| llvm | Provides back-end used by clang for BPF target |
| libbpf / libbpf-dev | Runtime library for loading and interacting with eBPF programs |
| bpftool | Inspects loaded eBPF programs and maps; required for eBPF unit tests |
| linux-tools-generic / bpftool | Ships `bpftool` on Debian-based systems |
| protobuf-compiler + libprotobuf | Compiles `.proto` definitions used in the XDS API layer |
| libprotobuf-c / protobuf-c-compiler | C bindings for protobuf, used by `api/v2-c` |
| libboundscheck | Memory safety library; auto-installed from source if unavailable |
| gcc-multilib | 32-bit headers needed during compilation on amd64 |

---

## Repository Structure

```text
kmesh/
├── api/            XDS-compatible protobuf models and generated C bindings
├── bpf/            eBPF programs and BPF-map deserialization library
│   ├── include/    Shared BPF headers
│   └── kmesh/      Traffic orchestration eBPF programs
├── build/          Dockerfiles and service configuration files
├── cniplugin/      CNI plugin (kmesh-cni)
├── common/         Shared configuration (golangci-lint config lives here)
├── config/         Runtime configuration files
├── ctl/            kmeshctl CLI source
├── daemon/         kmesh-daemon entry point and manager
├── deploy/         Kubernetes manifests and Helm charts
├── docs/           Documentation (you are here)
├── hack/           Developer scripts (formatting, linting, test runners)
├── kernel/         Kernel module source (kmesh.ko)
├── mk/             Makefile include fragments and pkg-config files
├── oncn-mda/       MDA core component (built with cmake)
├── pkg/            Library packages used by kmesh-daemon
│   ├── auth/       Authorization logic
│   ├── bpf/        BPF program lifecycle management
│   ├── cache/      XDS configuration cache
│   ├── controller/ XDS and workload controllers
│   ├── dns/        DNS resolution support
│   ├── status/     Status and debug HTTP server
│   └── ...
├── samples/        Example configurations
├── test/           E2E tests, BPF unit tests, performance tests
└── third_party/    Vendored third-party dependencies
```

---

## Setting Up the Environment

Install build dependencies with:

```bash
make prepare-dev
```

This script (`hack/golangci-lint-prepare.sh` + `kmesh_compile_env_pre.sh`) installs the required
packages for your distribution (Debian/Ubuntu via `apt`, Red Hat/CentOS/openEuler via `yum`) and
configures the build environment.

Pull the pre-built build image so it is available before your first build:

```bash
docker pull ghcr.io/kmesh-net/kmesh-build:latest
```

---

## Building Kmesh

### Build from Source

Kmesh compiles inside a Docker container named `kmesh-build`. Run as root or with `sudo`:

```bash
sudo make build
```

This invokes `./kmesh_compile.sh`, which starts the build container and produces binaries under
`out/<arch>/`:

| Binary | Description |
|---|---|
| `kmesh-daemon` | Node-level daemon; manages eBPF programs and subscribes to XDS |
| `kmesh-cni` | CNI plugin |
| `kmeshctl` | CLI for interacting with a running Kmesh deployment |
| `mdacore` | MDA core component |

Along with supporting shared libraries (`libbpf.so`, `libkmesh_deserial.so`, etc.).

### Build Docker Image

```bash
make docker
```

Custom hub, target, and tag:

```bash
make docker HUB=ghcr.io/kmesh-net TARGET=kmesh TAG=latest
```

### Clean Build Artifacts

The build process modifies some generated files. **Always run `make clean` before staging changes
for a commit**:

```bash
make clean
```

This removes build output, stops the `kmesh-build` container, and restores the auto-generated
files that were modified during the build.

---

## Running Unit Tests

### Go Unit Tests

Run in Docker (default, matches CI):

```bash
make test
```

Run locally (requires the project to have been built first):

```bash
make test RUN_IN_CONTAINER=0
```

Or invoke the test runner script directly:

```bash
# Run in Docker
./hack/run-ut.sh --docker

# Run locally
./hack/run-ut.sh --local
```

The test target is `./pkg/...`. To run tests for a specific package or test case, set
`TEST_PKG` or `TEST_TARGET`:

```bash
TEST_PKG=./pkg/controller/... make test RUN_IN_CONTAINER=0
```

Generate a coverage report (as done in CI):

```bash
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$PWD/api/v2-c:$PWD/bpf/deserialization_to_bpf_map \
  PKG_CONFIG_PATH=$PWD/mk \
  go test -gcflags=all=-l -race -v -vet=off -coverprofile=coverage.out ./pkg/...
```

### eBPF Unit Tests

eBPF unit tests exercise BPF programs using the framework documented in
[BPF Unit Tests](unit_test_doc.md).

Run in Docker:

```bash
make ebpf_unit_test
```

Run locally:

```bash
make ebpf_unit_test RUN_IN_CONTAINER=0
```

---

## Coding Conventions

Kmesh enforces conventions through automated tooling. Run all formatters with:

```bash
make format
```

This runs:

| Tool | Scope | Notes |
|---|---|---|
| `gofmt -w -s` | All Go files | Standard Go formatting |
| `clang-format -i` | All `.c` and `.h` files | Excludes `.pb-c` generated files |
| `shfmt -w -s -ln=bash` | All shell scripts | Installed via `go install mvdan.cc/sh/v3/cmd/shfmt` |
| `markdownlint-cli2 --fix` | All `.md` files | Run via Docker (skipped in CI) |

Run the linter:

```bash
golangci-lint run --config=common/config/.golangci.yaml
```

Active linters: `gofmt`, `goimports`, `govet`, `depguard`, `errcheck`, `gosimple`,
`ineffassign`, `staticcheck`, `typecheck`, `unused`, `misspell`, `whitespace`.

**`goimports` import ordering**: local packages (`kmesh.net/...`) must be grouped separately
from third-party imports. The `goimports` linter enforces this with
`local-prefixes: kmesh.net`.

**Package dependencies**: the following imports are banned (use the replacements shown):

| Banned | Use instead |
|---|---|
| `github.com/golang/protobuf` | `google.golang.org/protobuf` |
| `gopkg.in/yaml.v2`, `gopkg.in/yaml.v3`, `github.com/ghodss/yaml` | `sigs.k8s.io/yaml` |

**Before opening a PR**, run the generation check to ensure all generated files are up to date:

```bash
make gen-check
# or, if it requires elevated path access:
sudo env PATH=$PATH make gen-check
```

Check copyright headers:

```bash
make copyright-check
```

---

## Running Kmesh Locally with Kind

[Kind](https://github.com/kubernetes-sigs/kind) (Kubernetes in Docker) is the officially
documented and tested local development environment for Kmesh. **Linux kernel >= 5.10 is
required** even when using Kind, because the eBPF programs run on the host kernel.

Other local Kubernetes tools such as Minikube and K3s are not currently documented or tested
for Kmesh development. They may work, but no setup instructions exist in this repository.

### Prerequisites

- Docker
- Linux kernel >= 5.10 (`uname -r` to check)
- `kubectl` ([install guide](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/))

### Creating a Kind Cluster

Install `kind`:

```bash
wget -O kind https://github.com/kubernetes-sigs/kind/releases/download/v0.23.0/kind-linux-amd64
chmod +x kind
sudo mv kind /usr/bin/
```

Create a cluster (example with a control-plane and two workers):

```bash
kind create cluster --image=kindest/node:v1.23.17 --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
- role: worker
EOF
```

### Deploying Kmesh on Kind

Install `istioctl`:

```bash
curl -L https://istio.io/downloadIstio | sh -
chmod +x istio-*/bin/istioctl
sudo mv istio-*/bin/istioctl /usr/bin/
```

Install Istio. For **Dual-Engine Mode**, deploy Istio in ambient mode:

```bash
istioctl install --set profile=ambient
```

For **Kernel-Native Mode**:

```bash
istioctl install
```

Then follow the [Kmesh Quick Start](https://kmesh.net/en/docs/setup/quickstart/) to deploy Kmesh
into the cluster.

### Developing and Testing Code Changes in Kind

1. Build the code:

    ```bash
    sudo make build
    ```

2. Build a local Docker image:

    ```bash
    docker build -f build/docker/kmesh.dockerfile -t $IMAGE_NAME .
    ```

3. Load the image into the Kind cluster:

    ```bash
    kind load docker-image $IMAGE_NAME --name $CLUSTER_NAME
    ```

4. Update the Kmesh DaemonSet to use your image:

    ```bash
    kubectl edit ds kmesh -n kmesh-system
    ```

    Change the image field to `$IMAGE_NAME`, save, and wait for pods to restart:

    ```bash
    kubectl get po -n kmesh-system -w
    ```

5. Clean generated files before committing:

    ```bash
    make clean
    ```

---

## Debugging Tips

**View Kmesh daemon logs:**

```bash
kubectl logs $KMESH_POD -n kmesh-system
```

**Adjust log verbosity at runtime (Go-side):**

```bash
kmeshctl log $KMESH_POD --set default:debug
```

**Adjust eBPF log verbosity:**

```bash
kmeshctl log $KMESH_POD --set bpf:debug
```

On kernels >= 5.13 BPF log messages are forwarded to user space and appear in the daemon log
with `subsys=ebpf`. On older kernels, read them directly with bpftool:

```bash
bpftool prog tracelog
```

**Inspect eBPF maps and programs:**

```bash
bpftool map list
bpftool prog list
```

**Check pod and DaemonSet status:**

```bash
kubectl get po -n kmesh-system
kubectl describe ds kmesh -n kmesh-system
kubectl describe po $KMESH_POD -n kmesh-system
```

**Dump XDS configuration via kmeshctl:**

```bash
kmeshctl dump ads
```

---

## Development Workflow

1. **Fork** the repository on GitHub and clone your fork:

    ```bash
    git clone https://github.com/<your-username>/kmesh.git
    cd kmesh
    git remote add upstream https://github.com/kmesh-net/kmesh.git
    ```

2. **Sync** with upstream before starting work:

    ```bash
    git fetch upstream
    git checkout -b <your-branch> upstream/main
    ```

3. **Make changes**, then run:

    ```bash
    make gen-check          # regenerate and verify generated files
    make format             # format all code
    make copyright-check    # verify copyright headers
    make test               # run Go unit tests
    make ebpf_unit_test     # run eBPF unit tests
    make build              # compile the project
    make clean              # restore generated files before committing
    ```

4. **Commit** following [conventional commit message guidelines](https://chris.beams.io/posts/git-commit/).
   Kmesh requires a DCO sign-off on every commit:

    ```bash
    git commit -s -m "component: short summary of the change"
    ```

5. **Push** to your fork and open a pull request against `kmesh-net/kmesh:main`.

For more details on the contribution process, see [CONTRIBUTING.md](../../CONTRIBUTING.md).

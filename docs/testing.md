
# Kmesh Developer Testing Guide

This document provides detailed instructions for running unit tests in the Kmesh project. It outlines how and where tests are executed, how to prepare your development environment, how to troubleshoot common problems, and how to adapt based on platform.

## Who Is This For

- New contributors preparing to submit a pull request with test coverage  
- Developers verifying changes involving eBPF or Go modules  
- Users on Apple Silicon, UTM, Raspberry Pi, or similar ARM-based setups  

## Types of Tests in Kmesh

| Type         | Location                           | Command                              |
|--------------|-------------------------------------|---------------------------------------|
| Go Unit Test | All Go modules (e.g. pkg/, cmd/)    | `go test ./...`                       |
| BPF UT       | test/bpf_ut/                        | `make -C test/bpf_ut test`            |
| Shell-based  | test/runtest.sh                     | `bash test/runtest.sh`                |
| Integration  | test/e2e/                           | `go test ./test/e2e/...`              |

Integration tests require a configured cluster with Kmesh deployed.

## Recommended Approach

| Platform                          | Suggested Method                     |
|-----------------------------------|--------------------------------------|
| Linux with supported kernel (5.10+) | Local testing with `make test`       |
| macOS on Apple Silicon / UTM / ARM | Use Dockerized testing scripts       |

## Running Unit Tests

### Option 1: Run Inside Docker

Use Docker for isolated and consistent builds across systems.

```bash
./hack/run-ut.sh --docker
```

This script:
-Builds the project inside a Docker container  
-Runs tests with required environment and flags

If Docker permission fails, refer to the troubleshooting section.

### Option 2: Run Locally (Linux only)

Run tests directly on a supported kernel version.

```bash
./hack/run-ut.sh --local
```

Or specify the Make variable directly:

```bash
make test RUN_IN_CONTAINER=0
```

Ensure your system includes:

- clang  
- llvm  
- libelf-dev  
- protobuf and protobuf-c  
- Go version 1.22 or newer

## Manual Testing

Manually invoke Go unit tests using the appropriate environment configuration:

```bash
export ROOT_DIR=$(pwd)
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
export PKG_CONFIG_PATH=$ROOT_DIR/mk
export C_INCLUDE_PATH=$ROOT_DIR/bpf/include:$C_INCLUDE_PATH

go generate ./bpf/kmesh/bpf2go/...
go test ./... -gcflags="all=-N -l"
```

Use the gcflags option to prevent the Go compiler from inlining functions. This is required when using patching libraries like gomonkey.

## Troubleshooting and Known Issues

### Missing BPF Object Files

Error:

pattern kmeshcgroupskb_bpfel.o: no matching files found

Fix:

```bash
cd bpf/kmesh/bpf2go
go generate
```

Also run:

```bash
cd bpf/kmesh/bpf2go/kernelnative/normal
go generate

cd ../dualengine
go generate

cd ../general
go generate
```

If a folder like kernelnative/enhanced is referenced but does not exist, verify its status in the upstream repository.

### go.mod Version Error

If you see:

invalid go version '1.23.0'

Edit go.mod and update:

go 1.23

Do not append .0 to the version number.

### Docker Permission Denied

Error:

docker: permission denied while connecting to /var/run/docker.sock

Fix:

```bash
sudo usermod -aG docker $USER
```

Then log out and back in, or reboot.

To verify Docker access:

```bash
docker run hello-world
```

### Missing securec Headers or libboundscheck

When using Docker, the build may fail due to missing native libraries such as securec.

There are two options:
-Enter the Docker container and install needed packages manually  
-Ask maintainers to include securec in the build image or offer an official workaround  

## Verifying BPF Unit Tests

To verify BPF-specific tests:

```bash
make -C test/bpf_ut test
```

Install required dependencies if not already installed:

```bash
sudo apt install clang llvm libelf-dev
```

## Verifying Shell Tests

Run high-level shell-based tests using:

```bash
bash test/runtest.sh
```

These tests expect a clean Kmesh deployment and a functioning Kubernetes with Istio and Kmesh configured.

## Summary

| Feature                  | Run Method                            |
|--------------------------|----------------------------------------|
| Run all tests (Docker)   | `./hack/run-ut.sh --docker`           |
| Run all tests (local)    | `./hack/run-ut.sh --local`            |
| Manual test              | `go test ./...` with environment set  |
| Regenerate .o files      | `go generate` in bpf2go directories   |
| Fix Docker error         | Add user to docker group              |
| Go version requirement   | Go 1.22 or higher                     |

## Still Stuck

If problems persist, file an issue on GitHub or ask questions in the Kmesh community. Some test workflows may be improved in future if official support for ARM/UTM or Docker-based BPF builds stabilizes.

Contributed by: AkarshSahlot  
Tested on: Ubuntu (ARM64) via UTM  
Updated: August 2025


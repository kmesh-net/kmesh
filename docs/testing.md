
#  Kmesh Developer Testing Guide

This document provides detailed instructions for running unit tests in the [Kmesh](https://github.com/kmesh-net/kmesh) project. It covers how and where tests are run, how to set up the environment, how to troubleshoot issues, and platform-specific recommendations—based on real-world experiences.

## Who Is This For?

- New contributors looking to run tests before submitting changes  
- Developers debugging eBPF generation or Go tests  
- Anyone working on systems with ARM (Apple Silicon, Raspberry Pi) or virtual machines (UTM, Docker)

##  Types of Tests in Kmesh

| Type         | Where                              | Trigger command                        |
|--------------|-------------------------------------|----------------------------------------|
| Go Unit Test | All Go modules (cmd/, pkg/, etc.)   | `go test ./...`                        |
| BPF UT       | test/bpf_ut/                        | `make -C test/bpf_ut test`             |
| Shell-based  | test/runtest.sh                     | `bash test/runtest.sh`                 |
| Integration  | test/e2e/                           | `go test ./test/e2e/...` (requires clean cluster) |

## Recommended Approach

Depending on your operating system and architecture, choose one:

| Platform                           | Recommended Way to Run Tests          |
|------------------------------------|--------------------------------------|
| Linux with supported kernel (5.10+) | Run locally via `make test`         |
| macOS M1 / UTM / other VM or ARM   | Run in Docker using Kmesh's scripts |

##  Running Unit Tests

### Option 1: Run Inside Docker (Recommended on macOS M1/ARM)

Make sure Docker is installed and running, and that your user has permission to run Docker containers (consult _“Troubleshooting”_ if not).

```bash
./hack/run-ut.sh --docker
```

This will:
- Build the project in a portable Docker environment
- Run unit tests with all proper flags and file generation

 If you see an error like `permission denied /var/run/docker.sock`, see troubleshooting below.

### Option 2: Run Natively (for Linux with 5.10+ kernel)

Installs and runs tests directly on your system:

```bash
./hack/run-ut.sh --local
```

Or set the env variable directly:

```bash
make test RUN_IN_CONTAINER=0
```

Ensure you have:
- clang, llvm, libelf-dev, libprotobuf, protobuf-c, and bpf dependencies
- go version ≥ 1.22 (1.23 recommended)

## Manual Testing (Advanced)

To test individual modules or debug test behavior, configure the environment:

```bash
export ROOT_DIR=$(pwd)
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
export PKG_CONFIG_PATH=$ROOT_DIR/mk
export C_INCLUDE_PATH=$ROOT_DIR/bpf/include:$C_INCLUDE_PATH

go generate ./bpf/kmesh/bpf2go/...
go test ./... -gcflags="all=-N -l"
```

Use `-gcflags="all=-N -l"` to disable inlining for tests that depend on monkey-patching (e.g. using gomonkey).

## Troubleshooting & Known Issues

###  Missing `.o` Files (Go Test Fails with Pattern Errors)

Symptom:

```
pattern kmeshcgroupskb_bpfel.o: no matching files found
```

Fix:

```bash
cd bpf/kmesh/bpf2go
go generate
```

Repeat from inside these subdirectories:

```bash
cd bpf/kmesh/bpf2go/kernelnative/normal
go generate

cd ../dualengine
go generate

cd ../general
go generate
```

If folders like `/enhanced` are missing, confirm if they exist in the latest repo HEAD.

###  go.mod error: `invalid go version '1.23.0'`

Fix: edit the first line of your `go.mod` file to this:

```go
go 1.23
```
(_No extra `.0`_)

###  Docker Permission Denied

Symptom:

```
docker: permission denied while connecting to /var/run/docker.sock
```

Fix:

```bash
sudo usermod -aG docker $USER
```

Then reboot or log out and back in.

Test with:
```bash
docker run hello-world
```

###  Missing `securec/securec.h` or `libboundscheck.so`

If running inside Docker:
- The image might be missing `libsecurec-devel` or securec headers (note: this is a known limitation).
- Either debug by entering the container manually, or reach out to maintainers for advice.

##  Verifying BPF Unit Tests

The BPF test logic is here:

```bash
make -C test/bpf_ut test
```

Dependencies often needed:

```bash
sudo apt install clang llvm libelf-dev
```

##  Verifying Shell Tests

```bash
bash test/runtest.sh
```

Be aware: It may expect a clean Kmesh deployment and cluster, and could fail if Istio/K8s aren’t running correctly.

##  Summary

| Feature                  | Run Method                       |
|--------------------------|----------------------------------|
| Run all tests (Docker)   | `./hack/run-ut.sh --docker`     |
| Run all tests (local)    | `./hack/run-ut.sh --local`      |
| Manual test              | `go test ./...` after `go generate` |
| Regenerate BPF .o files  | `go generate` inside bpf2go packages |
| Fix Docker error         | Add user to `docker` group       |
| Go version requirement   | Go ≥ 1.22 (1.23 if supported)    |

##  Still Stuck?

Open an issue on GitHub or ask in the Kmesh community Slack/GitHub discussions. Running all tests on ARM-based systems may require assistance until better Docker support or multi-arch images improve.

---  
> _Contributed by: [AkarshSahlot] — based on real testing on Ubuntu (ARM64) in UTM_  
> _Updated: August 2025_

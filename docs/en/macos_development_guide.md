# macOS Development Guide

Kmesh is a high-performance service mesh data plane that relies heavily on Linux-specific kernel features, particularly **eBPF (Extended Berkeley Packet Filter)**. Since macOS uses the Darwin kernel, you cannot run Kmesh natively on macOS.

This guide provides several ways for macOS developers to set up a compatible environment for contributing to Kmesh.

---

## Development Options Overview

| Option | Ease of Use | Performance | BPF Support | Recommended |
| :--- | :---: | :---: | :---: | :---: |
| **UTM / Virtualizations** | Good | High | Full | **Yes** |
| **GitHub Codespaces** | Easy | Medium | Full | **Yes** |
| **Dual Boot** | Hard | Native | Full | Only for Intel |
| **Lima** | Easy | High | Limited | No (Kernel Panics) |
| **Docker Desktop** | Easy | Medium | Limited | No |

---

## Known Limitations

1. **Docker Desktop**: While Docker Desktop for Mac runs a Linux VM, it does not provide the full kernel headers and eBPF support required for Kmesh's advanced data plane features.
2. **Lima**: Lima is a popular tool for running Linux VMs on macOS, but Kmesh developers have reported kernel panics and BPF operation failures when using Lima.
3. **Apple Silicon (M1/M2/M3)**: Ensure you use an **ARM64** Linux distribution in your VM to avoid the massive performance penalty of x86 emulation.

---

## What you can do directly on macOS

Even without a Linux environment, you can perform several tasks natively on macOS:

- **Go Development**: You can write and compile the Go components (daemon, kmeshctl).
- **Static Analysis**: Run initial `go vet` or basic linting.
- **Documentation**: Write and preview Markdown documentation.
- **API/Proto**: Generate code from Protobuf definitions.

---

## Recommended Setup: UTM with Ubuntu

[UTM](https://getutm.app/) is a powerful virtualization tool for macOS based on QEMU. It provides better performance and integration for ARM64 Linux VMs on Apple Silicon.

### Step 1: Install UTM and Ubuntu

1. Download and install **UTM**.
2. Download the **Ubuntu Server for ARM** (or AMD64 if on Intel) ISO image.
3. Create a new VM in UTM:
   - Select **Virtualize** (not Emulate).
   - Allocate at least 4GB RAM and 4 CPU cores.
   - Attach the Ubuntu ISO and follow the installation steps.

### Step 2: Install Development Dependencies

Once your Ubuntu VM is running, install the core dependencies:

```bash
sudo apt update && sudo apt install -y build-essential git curl wget clang llvm pkg-config libbpf-dev
```

### Step 3: Install Go (Recommended: 1.24.2)

Kmesh uses Go 1.24.2. Install it in your VM:

```bash
GO_VERSION=1.24.2
# For Apple Silicon (ARM64)
wget https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz
# For Intel Macs (AMD64)
# wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-*.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo "export PATH=\$PATH:$(/usr/local/go/bin/go env GOPATH)/bin" >> ~/.bashrc
source ~/.bashrc
```

### Step 4: Shared Folders (VirtioFS)

To work on code using your macOS editor while building in the VM:

1. In UTM VM settings, go to **Sharing** and add a directory. Select **VirtioFS**.
2. Inside the VM, mount the shared folder:

```bash
sudo mkdir -p /mnt/kmesh
sudo mount -t virtiofs share /mnt/kmesh
```

---

## Development Workflow

### Connecting with VS Code

We recommend using [VS Code Remote - SSH](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-ssh) to develop inside your VM. This allows you to use your macOS VS Code interface while all language servers and builds run in the Linux environment.

### Building Kmesh

Inside your VM/Shared folder:

```bash
# Build the project (includes BPF compilation)
make build
```

### Running Tests

Kmesh includes both standard Go tests and BPF-specific tests.

```bash
# Run Go unit tests
# Note: Some tests in /pkg/ may still fail or be skipped if BPF is not available
go test ./pkg/... -v

# Run BPF unit tests
make ebpf_unit_test
```

### Generating Documentation

If you modify CLI commands or APIs, update the documentation:

```bash
make gen-kmeshctl-doc
```

---

## Troubleshooting

### BPF Filesystem not mounted

If BPF operations fail, ensure the BPF filesystem is mounted:

```bash
mount | grep bpf

# If not mounted, run:
sudo mount -t bpf none /sys/fs/bpf
```

### Shared Folder Permissions

If you cannot write to the shared folder, ensure your user has the correct permissions or use `mount` options to map your UID:

```bash
sudo mount -t virtiofs -o uid=$(id -u),gid=$(id -g) share /mnt/kmesh
```

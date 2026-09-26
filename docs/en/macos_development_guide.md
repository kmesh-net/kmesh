# macOS Developer Guide for Kmesh

This guide helps macOS developers set up a working environment for Kmesh development. Since Kmesh relies heavily on eBPF/BPF features that require a Linux kernel, macOS users need to use virtualization or dual-boot solutions.

## Overview

Kmesh requires Linux with BPF support for its core functionality. macOS developers have several options:

| Option | BPF Support | Performance | Ease of Setup | Recommended |
| ------ | ----------- | ----------- | ------------- | ----------- |
| **UTM (Ubuntu VM)** | ✅ Full | Good | Easy | ✅ Yes |
| **Dual-boot Ubuntu** | ✅ Full | Best | Moderate | ✅ Yes |
| **Lima** | ❌ Limited | Good | Easy | ❌ No |
| **Docker Desktop** | ❌ None | Good | Easy | ❌ No |

## ⚠️ Known Limitations

### Lima VM - Not Recommended for Kmesh

While Lima is popular for running Linux containers on macOS, it has significant limitations for Kmesh development:

- **BPF operations consistently fail or cause kernel panics**
- Basic Go tests may pass, but any BPF-related functionality will not work
- This affects all Kmesh features that depend on eBPF (which is most of them)
- Multiple Lima versions have been tested with the same outcome

**Do not use Lima for Kmesh development involving BPF features.**

### Docker Desktop - Not Recommended

Docker Desktop on macOS runs containers in a lightweight VM that doesn't expose full BPF capabilities needed for Kmesh development.

## Option: Continue Developing on macOS (Limited)

If you prefer to continue developing directly on macOS without a VM or dual-boot, you can still contribute to certain parts of Kmesh that don't require BPF. Here's what you can and cannot do:

### ✅ What You CAN Do on macOS

| Area | Description |
| ---- | ----------- |
| **Go code development** | Write, edit, and refactor Go code |
| **Code review** | Review PRs and provide feedback |
| **Documentation** | Write and update documentation |
| **Unit tests (non-BPF)** | Run tests that don't require BPF/Linux kernel |
| **API/protobuf work** | Work on API definitions and protobuf files |
| **CI/CD scripts** | Develop build scripts and GitHub Actions |
| **Frontend/CLI tools** | Work on `kmeshctl` and other CLI components |
| **Code linting** | Run linters and fix style issues |

### ❌ What You CANNOT Do on macOS

| Area | Reason |
| ---- | ------ |
| **BPF program development** | Requires Linux kernel |
| **eBPF map operations** | Linux-only feature |
| **Full integration tests** | Require BPF subsystem |
| **Kernel module work** | Linux-specific |
| **End-to-end testing** | Requires full Kmesh runtime |
| **Performance testing** | Requires real BPF execution |

### Setting Up macOS for Limited Development

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go

# Verify Go installation
go version

# Install development tools
brew install git make protobuf protoc-gen-go

# Clone Kmesh repository
git clone https://github.com/kmesh-net/kmesh.git
cd kmesh

# Run non-BPF unit tests (some tests will be skipped)
go test ./pkg/... -v -short

# Run linting
brew install golangci-lint
golangci-lint run

# Generate kmeshctl documentation
make gen-kmeshctl-doc
```

### Recommended Workflow for macOS-Only Developers

1. **Develop and test locally** - Write code and run available unit tests
2. **Use CI for full testing** - Push to a branch and let GitHub Actions run full tests in Linux
3. **Collaborate with Linux developers** - For BPF-specific features, pair with someone who has a Linux environment
4. **Use GitHub Codespaces** - Consider using [GitHub Codespaces](https://github.com/features/codespaces) for a cloud-based Linux development environment

### GitHub Codespaces Alternative

If you don't want to set up a local VM, you can use GitHub Codespaces:

1. Go to the [Kmesh repository](https://github.com/kmesh-net/kmesh)
2. Click the green **"Code"** button
3. Select **"Codespaces"** tab
4. Click **"Create codespace on main"**

This gives you a full Linux development environment in your browser with BPF support (depending on the codespace configuration).

## Recommended Option 1: UTM with Ubuntu VM

UTM is a free, open-source virtualization solution for macOS that works well with both Intel and Apple Silicon Macs.

### Prerequisites

- macOS 11.0 (Big Sur) or later
- At least 8GB RAM (16GB recommended)
- 50GB+ free disk space
- UTM app installed

### Step 1: Install UTM

Download UTM from:

- **App Store**: <https://apps.apple.com/app/utm-virtual-machines/id1538878817>
- **GitHub** (free): <https://github.com/utmapp/UTM/releases>

### Step 2: Download Ubuntu ISO

Download Ubuntu Server or Desktop ISO:

- **Ubuntu 22.04 LTS** (recommended): <https://ubuntu.com/download/server>
- For Apple Silicon (M1/M2/M3): Download the **ARM64** version
- For Intel Macs: Download the **AMD64** version

### Step 3: Create Ubuntu VM in UTM

1. Open UTM and click **"Create a New Virtual Machine"**
2. Select **"Virtualize"** (for native performance on Apple Silicon) or **"Emulate"** (for Intel on ARM)
3. Choose **"Linux"**
4. Browse and select the Ubuntu ISO file
5. Configure VM settings:
   - **Memory**: 8GB minimum (8192 MB)
   - **CPU Cores**: 4 or more
   - **Storage**: 50GB or more
6. Click **"Save"** and start the VM

### Step 4: Install Ubuntu

1. Boot the VM and follow the Ubuntu installation wizard
2. Choose minimal or full installation based on your preference
3. Create a user account and set a password
4. Complete installation and reboot

### Step 5: Configure Ubuntu for Kmesh Development

After Ubuntu is installed, open a terminal and run:

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential development tools
sudo apt install -y build-essential git curl wget

# Install Go (check https://go.dev/dl/ for latest version)
wget https://go.dev/dl/go1.21.5.linux-arm64.tar.gz  # For ARM64
# OR
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz  # For AMD64

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.*.tar.gz

# Add Go to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Verify Go installation
go version

# Install Docker
sudo apt install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# Install additional dependencies for Kmesh
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)
sudo apt install -y libelf-dev libssl-dev pkg-config
```

### Step 6: Clone and Build Kmesh

```bash
# Clone Kmesh repository
git clone https://github.com/kmesh-net/kmesh.git
cd kmesh

# Pull the build image
docker pull ghcr.io/kmesh-net/kmesh-build:latest

# Build Kmesh
make build

# Run tests
make test
```

### Step 7: Shared Folders (Optional)

To edit code on macOS and build in Ubuntu:

1. In UTM, go to VM settings → **Sharing**
2. Enable **Directory Sharing**
3. Add your macOS project folder
4. In Ubuntu, mount the shared folder:

```bash
# The shared folder should appear in /media/ or you can mount manually
# Note: virtiofsd runs on the host (managed by UTM), no installation needed in the guest
sudo mkdir -p /mnt/shared
sudo mount -t virtiofs share /mnt/shared
```

## Recommended Option 2: Dual-Boot Ubuntu

For the best performance and full compatibility, consider dual-booting Ubuntu alongside macOS.

### Benefits

- Native performance (no virtualization overhead)
- Full hardware access
- Complete BPF/eBPF support
- Best for intensive development and testing

### Requirements

- **Intel Mac**: Full support for dual-boot
- **Apple Silicon Mac**: Not supported for native dual-boot (use UTM instead)

### Setup Steps (Intel Mac)

1. **Backup your data** before proceeding
2. **Create a partition** for Ubuntu:
   - Open Disk Utility
   - Select your main drive
   - Click "Partition"
   - Add a new partition (minimum 50GB recommended)
   - Format as "MS-DOS (FAT)"
3. **Create a bootable Ubuntu USB**:
   - Download Ubuntu ISO
   - Use [balenaEtcher](https://www.balena.io/etcher/) to flash the ISO to a USB drive
4. **Install Ubuntu**:
   - Restart and hold Option (⌥) key during boot
   - Select the USB drive
   - Follow Ubuntu installation, selecting the partition you created
5. **Install rEFInd** (recommended) for a better boot manager:

   ```bash
   # On macOS, install via Homebrew
   brew install --cask refind
   ```

### Switching Between macOS and Ubuntu

- **On boot**: Hold Option (⌥) key to select OS
- **With rEFInd**: Select OS from the boot menu

## Verification: Test BPF Support

After setting up your environment, verify BPF works correctly:

```bash
# Check kernel version (should be 5.10+ for best Kmesh support)
uname -r

# Check BPF filesystem
mount | grep bpf

# If not mounted, mount it
sudo mount -t bpf bpf /sys/fs/bpf

# Test BPF capability
sudo bpftool version

# Run Kmesh eBPF unit tests
cd kmesh
make ebpf_unit_test
```

## Troubleshooting

### UTM VM won't start on Apple Silicon

- Ensure you downloaded the ARM64 version of Ubuntu
- Try allocating less memory if your Mac has limited RAM
- Update UTM to the latest version

### BPF programs fail to load

```bash
# Check if BPF is enabled
cat /boot/config-$(uname -r) | grep BPF

# Ensure you have proper permissions
sudo setcap cap_bpf,cap_net_admin=eip /path/to/kmesh-daemon

# Check dmesg for BPF-related errors
sudo dmesg | grep -i bpf
```

### Slow VM performance

- Increase allocated CPU cores and memory
- Use "Virtualize" mode instead of "Emulate" in UTM
- Enable hardware acceleration in VM settings
- Use an SSD for the VM disk image

### Shared folders not working

```bash
# Check if virtiofs module is loaded
lsmod | grep virtiofs

# Check dmesg for virtiofs errors
sudo dmesg | grep -i virtio

# Verify the mount point exists and try remounting
sudo mkdir -p /mnt/shared
sudo mount -t virtiofs share /mnt/shared

# If issues persist, check UTM sharing settings and restart the VM
```

## Development Workflow Tips

### Using VS Code Remote SSH

1. Install OpenSSH server in Ubuntu VM:

   ```bash
   sudo apt install -y openssh-server
   sudo systemctl enable ssh
   sudo systemctl start ssh
   ```

2. Get the VM's IP address:

   ```bash
   ip addr show
   ```

3. In VS Code on macOS:
   - Install "Remote - SSH" extension
   - Connect to `username@vm-ip-address`

### Port Forwarding for Testing

In UTM, configure port forwarding to access services running in the VM:

1. Go to VM settings → **Network**
2. Add port forwards (e.g., 8080:8080 for web services)

## Summary

For macOS developers working on Kmesh:

1. **Use UTM with Ubuntu** - Best balance of convenience and full BPF support
2. **Avoid Lima** - BPF features will not work properly
3. **Consider dual-boot** (Intel Macs only) for maximum performance
4. **Verify BPF support** before starting development

If you encounter issues not covered here, please open an issue on the [Kmesh GitHub repository](https://github.com/kmesh-net/kmesh/issues).

## Related Documentation

- [Kmesh Compilation Guide](kmesh_compile.md)
- [Kmesh Kernel Compilation](kmesh_kernel_compile.md)
- [Kmesh Support Matrix](kmesh_support.md)
- [Development in Kind](kmesh_deploy_and_develop_in_kind.md)

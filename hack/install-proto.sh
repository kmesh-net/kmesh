#!/bin/bash

function install_tool() {
	tool=${1}
	if command -v apt >/dev/null; then
		sudo apt-get update
		sudo apt-get install -y $tool
	elif command -v yum >/dev/null; then
		# yum install
		sudo yum install -y $tool
	fi
}

function install_protoc_binary_linux() {
	local version="$1"
	local arch_suffix="$2"
	local url="$3"

	wget "$url" -O "protoc-${version}-linux-${arch_suffix}.zip"
	unzip "protoc-${version}-linux-${arch_suffix}.zip" -d "protoc-${version}"
	sudo mv "protoc-${version}/bin/protoc" /usr/local/bin/
	rm -rf "protoc-${version}-linux-${arch_suffix}.zip" "protoc-${version}"
}

function install_protoc_binary_macos() {
	local version="$1"
	local arch_suffix="$2"
	local url="$3"

	curl -L "$url" -o "protoc-${version}-osx-${arch_suffix}.zip"
	unzip "protoc-${version}-osx-${arch_suffix}.zip" -d "protoc-${version}"
	mv "protoc-${version}/bin/protoc" /usr/local/bin/ || echo "Failed to move protoc to /usr/local/bin, please move it manually or add to PATH"
	rm -rf "protoc-${version}-osx-${arch_suffix}.zip" "protoc-${version}"
}

function install_protoc() {
	local arch
	local arch_suffix
	local download_url
	local installed_version
	local desired_version="28.1"
	local os_type

	# check the OS type
	os_type=$(uname -s)
	
	# check the architecture
	arch=$(uname -m)
	case "$arch" in
	x86_64)
		arch_suffix="x86_64"
		;;
	aarch64|arm64)
		arch_suffix="aarch_64"
		;;
	*)
		echo "Unsupported architecture: $arch"
		exit 1
		;;
	esac

	case "$os_type" in
	Linux*)
		download_url="https://github.com/protocolbuffers/protobuf/releases/download/v${desired_version}/protoc-${desired_version}-linux-${arch_suffix}.zip"
		;;
	Darwin*)
		download_url="https://github.com/protocolbuffers/protobuf/releases/download/v${desired_version}/protoc-${desired_version}-osx-${arch_suffix}.zip"
		;;
	*)
		echo "Unsupported operating system: $os_type"
		exit 1
		;;
	esac

	# Check if protoc is installed
	if command -v protoc >/dev/null 2>&1; then
		installed_version=$(protoc --version | awk '{print $2}')
		echo "Installed protoc version: $installed_version"
	else
		installed_version="none"
		echo "protoc is not installed."
	fi

	if [[ $installed_version != "$desired_version" ]]; then
		echo "Installing protoc version ${desired_version}..."
		case "$os_type" in
		Linux*)
			install_protoc_binary_linux "$desired_version" "$arch_suffix" "$download_url"
			;;
		Darwin*)
			install_protoc_binary_macos "$desired_version" "$arch_suffix" "$download_url"
			;;
		esac
	else
		echo "protoc is up-to-date."
	fi

	tools=()

	if command -v protoc >/dev/null; then
		echo "protoc already installed"
	else
		tools+=(protobuf-compiler)
	fi

	if command -v protoc-c >/dev/null; then
		echo "protoc-c already installed"
	else
		tools+=(protobuf-c-compiler)
	fi

	if [ ${#tools[@]} -gt 0 ]; then
		for element in "${tools[@]}"; do
			install_tool $element
		done
	fi

	if command -v protoc-gen-go >/dev/null; then
		installed_version=$(protoc-gen-go --version | awk '{print $2}')
		if [[ $installed_version == "v1.34.2" ]]; then
			echo "Installed protoc-gen-go version matches the desired version."
		else
			go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
		fi
	else
		go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
	fi
}

install_protoc

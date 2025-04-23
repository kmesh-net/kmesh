# libboundscheck is not available in some environments, install by source
function install_libboundscheck() {
	if [ ! -f /usr/local/lib/libboundscheck.so ]; then
		git clone https://github.com/openeuler-mirror/libboundscheck.git
		cd libboundscheck
		make CC=gcc
		cp lib/libboundscheck.so /usr/local/lib
		cp include/* /usr/include
		cd ../
		rm -rf libboundscheck
	fi
}

function dependency_pkg_install() {

	if command -v apt >/dev/null; then
		echo "Checking for required packages on a Debian-based system..."

		packages=(git make clang libbpf-dev llvm linux-tools-generic protobuf-compiler libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler cmake pkg-config gcc-multilib)

		update_needed=false
		for pkg in "${packages[@]}"; do
			if ! dpkg -s "$pkg" >/dev/null 2>&1; then
				update_needed=true
				break
			fi
		done

		if [ "$update_needed" = true ]; then
			apt-get update
		fi

		# Install each missing package
		for pkg in "${packages[@]}"; do
			if ! dpkg -s "$pkg" >/dev/null 2>&1; then
				echo "Installing $pkg..."
				apt-get install -y "$pkg"
			else
				echo "$pkg is already installed."
			fi
		done

		# Install libboundscheck if it’s not already present
		install_libboundscheck

	# Check if running on a Red Hat-based system (yum)
	elif command -v yum >/dev/null; then
		echo "Checking for required packages on a Red Hat-based system..."

		# List of required packages
		packages=(git make clang llvm libboundscheck protobuf protobuf-c protobuf-c-devel bpftool libbpf libbpf-devel cmake pkg-config glibc-devel libstdc++-devel)

		# Install each missing package
		for pkg in "${packages[@]}"; do
			if ! rpm -q "$pkg" >/dev/null 2>&1; then
				echo "Installing $pkg..."
				yum install -y "$pkg"
			else
				echo "$pkg is already installed."
			fi
		done
	fi
}

# fix bug in libbpf
function fix_libbpf_bug() {
	if ! grep -iq "#define SEC(name) __attribute__((section(name), used))" /usr/include/bpf/bpf_helpers.h; then
		LINENUMBER=$(grep -n '#define SEC(name)' /usr/include/bpf/bpf_helpers.h | cut -f1 -d:)
		if [[ -n $LINENUMBER ]]; then
			sed -i "${LINENUMBER} i #if __GNUC__ && !__clang__\n#define SEC(name) __attribute__((section(name), used))\n#else" /usr/include/bpf/bpf_helpers.h
			LINENUMBER=$((LINENUMBER + 8))
			sed -i "${LINENUMBER} a \\#endif" /usr/include/bpf/bpf_helpers.h
		fi
	fi
}

function adapt_low_version_kernel() {
	# adapt less insn in kernel 4.19, only 4096, so modify KMESH_PER_ENDPOINT_NUM into 15
	if [ "$(uname -r | cut -d '.' -f 1)" -le 4 ]; then
		sed -i 's/\(KMESH_PER_ENDPOINT_NUM\).*/\1 15/g' bpf/kmesh/ads/include/config.h
	fi
}

# Special case:
# There is a structure that is only defined in certain environments and is
# only used during the compilation stage. Therefore, the definition of this
# structure in the include directory is dynamically adjusted according to
# the current compilation environment during compilation.
function adapt_include_env {
	if grep -q "struct bpf_mem_ptr {" /usr/include/linux/bpf.h; then
		sed -i '/bpf_mem_ptr/{N;N;N;N;d;}' bpf/kmesh/ads/include/kmesh_common.h
	fi
}

function kmesh_set_env() {
	if [ "$(arch)" == "x86_64" ]; then
		export EXTRA_CDEFINE="-D__x86_64__"
		export C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu:$C_INCLUDE_PATH
	fi

	if [ "$(arch)" == "aarch64" ]; then
		export C_INCLUDE_PATH=/usr/include/aarch64-linux-gnu:$C_INCLUDE_PATH
	fi
	export EXTRA_GOFLAGS='-gcflags="-N -l" -buildmode=pie'
	export EXTRA_CFLAGS="-O0 -g"
}

function set_enhanced_kernel_env() {
	# we use /usr/include/linux/bpf.h to determine the runtime environment’s
	# support for kmesh. Considering the case of online image compilation, a
	# variable KERNEL_HEADER_LINUX_BPF is used here to specify the path of the
	# source of macro definition.
	# When using an online compiled image, /usr/include/linux/bpf.h in host
	# machine  will be mounted to config/linux-bpf.h.
	# Otherwise, /usr/include/linux/bpf.h from the current compilation
	# environment will be obtained
	export KERNEL_HEADER_LINUX_BPF=$ROOT_DIR/config/linux-bpf.h
	if [ ! -f "$KERNEL_HEADER_LINUX_BPF" ]; then
		export KERNEL_HEADER_LINUX_BPF=/usr/include/linux/bpf.h
	fi

	if grep -q "FN(parse_header_msg)" $KERNEL_HEADER_LINUX_BPF; then
		export ENHANCED_KERNEL="enhanced"
	else
		export ENHANCED_KERNEL="normal"
	fi
}

function prepare() {
	if [ "${SKIP_DEPENDENCY_INSTALL}" != "true" ]; then
		dependency_pkg_install
	fi
	fix_libbpf_bug
	adapt_low_version_kernel
	adapt_include_env
	kmesh_set_env
	bash kmesh_macros_env.sh
	bash kmesh_bpf_env.sh
}

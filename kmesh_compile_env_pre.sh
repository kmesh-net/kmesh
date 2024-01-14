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
    if command -v apt > /dev/null; then
	    # apt install 
	    apt-get update && apt-get install -y git make clang libbpf-dev llvm linux-tools-generic protobuf-compiler libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler cmake pkg-config
	    install_libboundscheck
    elif command -v yum > /dev/null; then
	    # yum install
	    yum install -y git make clang llvm libboundscheck protobuf protobuf-c protobuf-c-devel bpftool libbpf libbpf-devel cmake pkg-config
    fi
}

# fix bug in libbpf
function fix_libbpf_bug() {
    if ! grep -iq "#define SEC(name) __attribute__((section(name), used))" /usr/include/bpf/bpf_helpers.h; then
	    LINENUMBER=$(grep -n '#define SEC(name)' /usr/include/bpf/bpf_helpers.h | cut -f1 -d:)
	    if [[ ! -z "$LINENUMBER" ]]; then
		    sed -i "${LINENUMBER} i #if __GNUC__ && !__clang__\n#define SEC(name) __attribute__((section(name), used))\n#else" /usr/include/bpf/bpf_helpers.h
		    LINENUMBER=$((LINENUMBER+8))
		    sed -i "${LINENUMBER} a \\#endif" /usr/include/bpf/bpf_helpers.h
	    fi
    fi
}

function adapt_low_version_kernel() {
    # adapt less insn in kernel 4.19, only 4096, so modify KMESH_PER_ENDPOINT_NUM into 15
    if [ "$(uname -r | cut -d '.' -f 1)" -le 4 ]; then
            sed -i 's/\(KMESH_PER_ENDPOINT_NUM\).*/\1 15/g' bpf/kmesh/include/config.h
    fi
}

# Special case: 
# There is a structure that is only defined in certain environments and is 
# only used during the compilation stage. Therefore, the definition of this 
# structure in the include directory is dynamically adjusted according to 
# the current compilation environment during compilation.
function adapt_include_env {
    if grep -q "struct bpf_mem_ptr {" /usr/include/linux/bpf.h; then
        sed -i '/bpf_mem_ptr/{N;N;N;N;d;}' bpf/kmesh/include/kmesh_common.h
    fi
}

dependency_pkg_install
fix_libbpf_bug
adapt_low_version_kernel
adapt_include_env

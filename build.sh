#!/bin/bash
ROOT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

# adjust the range of BPF code compillation based on the kernel is enhanced
function bpf_compile_range_adjust() {
    if [ "$ENHANCED_KERNEL" == "enhanced" ]; then
            sed -i '/tracepoint/s/\(.*\)generate/\/\/go:generate/' bpf/kmesh/bpf2go/bpf2go.go
            sed -i '/sockops/s/\(.*\)generate/\/\/go:generate/' bpf/kmesh/bpf2go/bpf2go.go
    else
            sed -i '/tracepoint/s/\(.*\)generate/\/\/not go:generate/' bpf/kmesh/bpf2go/bpf2go.go
            sed -i '/sockops/s/\(.*\)generate/\/\/not go:generate/' bpf/kmesh/bpf2go/bpf2go.go
    fi
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
	    export ENHANCED_KERNEL="unenhanced"
    fi
}

function prepare() {
    bash kmesh_compile_env_pre.sh
    bash kmesh_macros_env.sh
    bash kmesh_bpf_env.sh
    if [ "$(arch)" == "x86_64" ]; then
            export EXTRA_CDEFINE="-D__x86_64__"
	    export C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu:$C_INCLUDE_PATH
    fi

    if [ "$(arch)" == "aarch64" ]; then
            export C_INCLUDE_PATH=/usr/include/aarch64-linux-gnu:$C_INCLUDE_PATH
    fi
    export EXTRA_GOFLAGS="-gcflags=\"-N -l\""
    export EXTRA_CFLAGS="-O0 -g"    
    
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.32.0
    export PATH="$PATH:$(go env GOPATH)/bin"
    bpf_compile_range_adjust
}

function install() {
    mkdir -p /etc/kmesh
    chmod 700 /etc/kmesh

    cp $ROOT_DIR/build/kmesh-start-pre.sh /usr/bin
    chmod 500 /usr/bin/kmesh-start-pre.sh
    cp $ROOT_DIR/build/kmesh-stop-post.sh /usr/bin
    chmod 500 /usr/bin/kmesh-stop-post.sh

    mkdir -p /etc/oncn-mda
    chmod 700 /etc/oncn-mda
    cp $ROOT_DIR/oncn-mda/etc/oncn-mda.conf /etc/oncn-mda/
    chmod 600 /etc/oncn-mda/oncn-mda.conf

    cp $ROOT_DIR/build/kmesh.service /usr/lib/systemd/system/
    chmod 600 /usr/lib/systemd/system/kmesh.service
    systemctl daemon-reload
}

function uninstall() {
    rm -rf /etc/kmesh
    rm -rf /usr/bin/kmesh-start-pre.sh
    rm -rf /usr/bin/kmesh-stop-post.sh
    rm -rf /etc/oncn-mda
    rm -rf /usr/share/oncn-mda
    rm -rf /usr/lib/systemd/system/kmesh.service
    systemctl daemon-reload
}

function clean() {
    rm -rf /etc/kmesh
    rm -rf /usr/bin/kmesh-start-pre.sh
    rm -rf /usr/bin/kmesh-stop-post.sh
}

set_enhanced_kernel_env

if [ "$1" == "-h"  -o  "$1" == "--help" ]; then
    echo build.sh -h/--help : Help.
    echo build.sh -b/--build: Build Kmesh.
    echo build.sh -i/--install: Install Kmesh.
    echo build.sh -c/--clean: Clean the built binary.
    echo build.sh -u/--uninstall: Uninstall Kmesh.
    exit
fi

if [ -z "$1" -o "$1" == "-b"  -o  "$1" == "--build" ]; then
    prepare
    make
    exit
fi

if [ "$1" == "-i"  -o  "$1" == "--install" ]; then
    make install
    install
    exit
fi

if [ "$1" == "-u"  -o  "$1" == "--uninstall" ]; then
    make uninstall
    uninstall
    exit
fi

if [ "$1" == "-c"  -o  "$1" == "--clean" ]; then
    make clean
    clean
    exit
fi

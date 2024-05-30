#!/bin/bash

function prepare() {
    local arch
    arch=$(get_arch)
    docker pull "ghcr.io/kmesh-net/kmesh-build-${arch}:latest"
}

function run_docker_container() {
    local arch
    arch=$(get_arch)
    local container_id
    container_id=$(docker run -itd --privileged=true \
        -v /usr/src:/usr/src \
        -v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h \
        -v /etc/cni/net.d:/etc/cni/net.d \
        -v /opt/cni/bin:/opt/cni/bin \
        -v /mnt:/mnt \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /lib/modules:/lib/modules \
        -v "$(pwd)":/kmesh \
        -v "$(go env GOCACHE)":/root/.cache/go-build \
        -v "$(go env GOMODCACHE)":/go/pkg/mod \
        --name kmesh-build "ghcr.io/kmesh-net/kmesh-build-${arch}:latest")

    echo "$container_id"
}

function get_arch() {
    if [ "$(arch)" == "x86_64" ]; then
        echo "x86"
    else
        echo "arm"
    fi
}

function build_kmesh() {
    local container_id=$1
    docker exec $container_id git config --global --add safe.directory /kmesh
    docker exec $container_id sh /kmesh/build.sh
    docker exec $container_id sh /kmesh/build.sh -i
    docker exec $container_id sh -c "$(declare -f copy_to_host); copy_to_host"
}

function copy_to_host() {
    local arch=""
    if [ "$(arch)" == "x86_64" ]; then
        arch="amd64"
    else
        arch="aarch64"
    fi

    mkdir -p "./out/$arch"
    mkdir -p "./out/$arch/ko"

    cp /usr/lib64/libkmesh_api_v2_c.so out/$arch
    cp /usr/lib64/libkmesh_deserial.so out/$arch
    cp /usr/lib64/libboundscheck.so out/$arch
    find /usr/lib64 -name 'libbpf.so*' -exec cp {} out/$arch \;
    find /usr/lib64 -name 'libprotobuf-c.so*' -exec cp {} out/$arch \;
    cp /usr/bin/kmesh-daemon out/$arch
    cp /usr/bin/kmesh-cni out/$arch
    cp /usr/bin/mdacore out/$arch
    if [ -f "/lib/modules/kmesh/kmesh.ko" ]; then
        cp /lib/modules/kmesh/kmesh.ko out/$arch/ko
    fi
}

function clean_container() {
    local container_id=$1
    docker rm -f $container_id
}

prepare
container_id=$(run_docker_container)
build_kmesh $container_id
clean_container $container_id

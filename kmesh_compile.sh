#!/bin/bash

function prepare() {
    docker pull ghcr.io/kmesh-net/kmesh-build:v0.2.0
}

function run_docker_container() {
    local container_id=$(docker run -itd --privileged=true \
        -v /usr/src:/usr/src \
        -v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h \
        -v /etc/cni/net.d:/etc/cni/net.d \
        -v /opt/cni/bin:/opt/cni/bin \
        -v /mnt:/mnt \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /lib/modules:/lib/modules \
        -v $(pwd):/kmesh \
        --name kmesh-build kmesh-build:v0.2.0)

    echo $container_id
}

function build_kmesh() {
    local container_id=$1
    docker exec $container_id sh /kmesh/build.sh
    docker exec $container_id sh /kmesh/build.sh -i
    docker exec $container_id sh -c "$(declare -f copy_to_host); copy_to_host"
}

function copy_to_host() {
    local dir=""
    if [ ! -d "./out" ]; then
        mkdir out
    fi

    if [ "$(arch)" == "x86_64" ]; then
        dir="amd64"
    else
        dir="aarch64"
    fi

    mkdir "./out/$dir"

    cp /usr/lib64/libkmesh_api_v2_c.so out/$dir
    cp /usr/lib64/libkmesh_deserial.so out/$dir
    cp /usr/lib64/libboundscheck.so out/$dir
    find /usr/lib64 -name 'libbpf.so*' -exec cp {} out/$dir \;
    find /usr/lib64 -name 'libprotobuf-c.so*' -exec cp {} out/$dir \;
    cp /usr/bin/kmesh-daemon out/$dir
    cp /usr/bin/kmesh-cmd out/$dir
    cp /usr/bin/kmesh-cni out/$dir
    cp /usr/bin/mdacore out/$dir
}

function clean_container() {
    local container_id=$1
    docker rm -f $container_id
}

prepare
container_id=$(run_docker_container)
build_kmesh $container_id
clean_container $container_id

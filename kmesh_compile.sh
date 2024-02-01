#!/bin/bash

KMESH_DIR=$(pwd)
container_id=$(docker run -itd --privileged=true -v /usr/src:/usr/src -v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h -v /etc/cni/net.d:/etc/cni/net.d -v /opt/cni/bin:/opt/cni/bin -v /mnt:/mnt -v /sys/fs/bpf:/sys/fs/bpf -v /lib/modules:/lib/modules -v ${KMESH_DIR}:/kmesh --name kmesh-build kmesh:build)
dir=""
function build() {
    docker exec $container_id  sh /kmesh/build.sh 
    docker exec $container_id  sh  /kmesh/build.sh -i 
}

function copy_to_host() {
    if [ ! -d "./out" ]; then
        mkdir out
    fi
    if [ "$(arch)" == "x86_64" ]; then
        mkdir ./out/amd64
        dir="amd64"
    else
        mkdir ./out/aarch64
        dir="aarch64"
    fi
    docker cp $container_id:/usr/lib64/libkmesh_api_v2_c.so out/$dir
    docker cp $container_id:/usr/lib64/libkmesh_deserial.so out/$dir
    docker cp $container_id:/usr/lib64/libboundscheck.so out/$dir
    docker exec $container_id find /usr/lib64 -name 'libbpf.so*' -print0 | xargs -0 -I {} docker cp $container_id:{} out/$dir
    docker exec $container_id find /usr/lib64 -name 'libprotobuf-c.so*' -print0 | xargs -0 -I {} docker cp $container_id:{} out/$dir
    docker cp $container_id:/usr/bin/kmesh-daemon out/$dir
    docker cp $container_id:/usr/bin/kmesh-cmd out/$dir
    docker cp $container_id:/usr/bin/kmesh-cni out/$dir
    docker cp $container_id:/usr/bin/mdacore out/$dir 
    docker cp $container_id:/usr/share/oncn-mda/sock_ops.c.o out/$dir 
    docker cp $container_id:/usr/share/oncn-mda/sock_redirect.c.o out/$dir
}

build
copy_to_host
#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
. $ROOT_DIR/hack/utils.sh
. $ROOT_DIR/kmesh_compile_env_pre.sh

kmesh_exec(){
    set_enhanced_kernel_env
    prepare
    go generate bpf/kmesh/bpf2go/bpf2go.go
}

function build_kmesh_bpf2go() {
    local container_id=$1
    docker exec $container_id git config --global --add safe.directory /kmesh
    docker exec -e VERSION=$VERSION $container_id ./hack/gen_bpf2go_exec.sh
}


container_id=$(run_docker_container)
build_kmesh_bpf2go $container_id
clean_container $container_id


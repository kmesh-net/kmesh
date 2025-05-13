#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
. $ROOT_DIR/hack/utils.sh
. $ROOT_DIR/kmesh_compile_env_pre.sh

function build_kmesh_bpf2go() {
	local container_id=$1
	docker exec $container_id git config --global --add safe.directory /kmesh
	docker exec -e VERSION=$VERSION $container_id ./hack/gen_bpf2go_exec.sh
}

container_id=$(run_docker_container)
build_kmesh_bpf2go $container_id
clean_container $container_id
make clean

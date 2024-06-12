#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

function run_go_ut() {
    local container_id=$1
    WORKSPACE=/kmesh
    docker exec $container_id go test -v -vet=off -coverprofile=coverage.out ./pkg/...
}

prepare
container_id=$(run_docker_container)
build_kmesh $container_id
run_go_ut $container_id
clean_container $container_id

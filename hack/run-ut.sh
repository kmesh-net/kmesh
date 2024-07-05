#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

function get_go_test_command() {
    if [ -z "$TEST_TARGET" ]; then
        echo "go test -v -race -vet=off ./pkg/..."
    else
        echo "go test -v -race -vet=off -run $TEST_TARGET ./pkg/..."
    fi
}

go_test_command=$(get_go_test_command)

function docker_run_go_ut() {
    local container_id=$1
    docker exec $container_id $go_test_command
}

function run_go_ut_local() {
    bash $ROOT_DIR/build.sh
    export PKG_CONFIG_PATH=$ROOT_DIR/mk
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
    eval "$go_test_command"  
}

function run_go_ut_in_docker() {
    prepare
    container_id=$(run_docker_container)
    build_kmesh $container_id
    docker_run_go_ut $container_id
    clean_container $container_id
}

function clean() {
    make clean $ROOT_DIR
}

# Running go ut with docker by default
if [ -z "$1" -o "$1" == "-d"  -o  "$1" == "--docker" ]; then
    run_go_ut_in_docker
    exit
fi

if [ "$1" == "-l"  -o  "$1" == "--local" ]; then
    run_go_ut_local
    exit
fi

if [ "$1" == "-h"  -o  "$1" == "--help" ]; then
    echo run-ut.sh -h/--help : Help.
    echo run-ut.sh -d/--docker: run go unit test in docker.
    echo run-ut.sh -l/--local: run go unit test locally.
    exit
fi

if [ "$1" == "-c"  -o  "$1" == "--clean" ]; then
    clean
    exit
fi 

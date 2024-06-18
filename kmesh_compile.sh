#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

prepare
container_id=$(run_docker_container)
build_kmesh $container_id
clean_container $container_id

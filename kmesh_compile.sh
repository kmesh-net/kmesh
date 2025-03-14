#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

bash kmesh_macros_env_kernel.sh
make kmesh-ko
container_id=$(run_docker_container)
build_kmesh $container_id
clean_container $container_id

sudo chmod -R a+r out/

#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

DOCKER_EBPF_TEST_COMMAND="make -C /kmesh/test/bpf_ut clean;make -C /kmesh/test/bpf_ut run"
LOCAL_EBPF_TEST_COMMAND="make -C $ROOT_DIR/test/bpf_ut clean;make -C $ROOT_DIR/test/bpf_ut run"

function docker_run_ebpf_ut() {
	local container_id=$1

	docker exec $container_id bash -c "$DOCKER_EBPF_TEST_COMMAND"

	exit_code=$?
	return $exit_code
}

function run_ebpf_ut_local() {
	bash $ROOT_DIR/build.sh
	export PKG_CONFIG_PATH=$ROOT_DIR/mk
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
	eval "$LOCAL_EBPF_TEST_COMMAND"
}

function run_ebpf_ut_in_docker() {
	container_id=$(run_docker_container)
	build_kmesh $container_id
	docker_run_ebpf_ut $container_id
	ut_exit_code=$?
	clean_container $container_id
	exit $ut_exit_code
}

function clean() {
	make clean $ROOT_DIR
}

TEST_FLAGS=""

if [[ $* == *"-v"* ]] || [[ $* == *"--verbose"* ]]; then
	TEST_FLAGS="$TEST_FLAGS V=1"
fi

DOCKER_EBPF_TEST_COMMAND="$DOCKER_EBPF_TEST_COMMAND $TEST_FLAGS"
LOCAL_EBPF_TEST_COMMAND="$LOCAL_EBPF_TEST_COMMAND $TEST_FLAGS"

# Running ebpf ut with docker by default
if [ -z "$1" -o "$1" == "-d" -o "$1" == "--docker" ]; then
	run_ebpf_ut_in_docker
	exit
fi

if [ "$1" == "-l" -o "$1" == "--local" ]; then
	run_ebpf_ut_local
	exit
fi

if [ "$1" == "-h" -o "$1" == "--help" ]; then
	echo run-ebpf-ut.sh -h/--help : Help.
	echo run-ebpf-ut.sh -d/--docker: run ebpf unit test in docker.
	echo run-ebpf-ut.sh -l/--local: run ebpf unit test locally.
	exit
fi

if [ "$1" == "-c" -o "$1" == "--clean" ]; then
	clean
	exit
fi

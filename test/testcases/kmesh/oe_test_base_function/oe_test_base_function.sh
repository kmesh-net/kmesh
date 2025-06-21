#!/usr/bin/bash

source ${OET_PATH}/libs/locallibs/common_lib.sh
source ../libs/common.sh

CURRENT_PATH=$(pwd)

function pre_test() {
	LOG_INFO "Start environmental preparation."

	env_init

	LOG_INFO "End of environmental preparation!"
}

function run_test() {
	LOG_INFO "Start testing..."

	set -e

	#start fortio server
	start_fortio_server -http-port 127.0.0.1:11466

	#start kmesh-daemon
	start_kmesh

	#use kmesh-cmd load conf and check conf load ok
	load_kmesh_config

	#use bpftool trace test result
	curl_test

	LOG_INFO "Finish test!"
}

function post_test() {
	LOG_INFO "start environment cleanup."

	cleanup

	LOG_INFO "Finish environment cleanup!"
}

main "$@"

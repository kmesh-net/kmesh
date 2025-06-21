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

	# exits the shell when $? is not 0
	set -e

	# start fortio server 11466
	# start fortio server 11488
	start_fortio_server -http-port 127.0.0.1:11466 -echo-server-default-params="header=server:1"
	start_fortio_server -http-port 127.0.0.1:11488 -echo-server-default-params="header=server:2"

	# start kmesh-daemon
	start_kmesh

	# use kmesh-cmd load conf and check conf load ok
	load_kmesh_config

	# load balancing test
	# round robin
	curl -v http://127.0.0.1:23333 >tmp_trace.log 2>&1
	curl -v http://127.0.0.1:23333 >>tmp_trace.log 2>&1
	grep 'Server: 1' tmp_trace.log && grep 'Server: 2' tmp_trace.log
	CHECK_RESULT $? 0 0 "bad balancing"

	LOG_INFO "Finish test!"
}

function post_test() {
	LOG_INFO "start environment cleanup."

	cleanup

	LOG_INFO "Finish environment cleanup!"
}

main "$@"

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

	# curl header is end-user:jason route to 11466
	# else route to 11488
	for ((i = 0; i < 10; i++)); do
		curl --header "end-user:jason" -v http://127.0.0.1:23333 >>tmp_trace1.log 2>&1
		curl -v http://127.0.0.1:23333 >>tmp_trace2.log 2>&1
	done

	grep 'Server: 1' tmp_trace1.log && grep 'Server: 2' tmp_trace2.log && grep 'Server: 2' tmp_trace1.log || grep 'Server: 1' tmp_trace2.log || echo 'OK'
	CHECK_RESULT $_ OK 0 "bad route"

	LOG_INFO "Finish test!"
}

function post_test() {
	LOG_INFO "start environment cleanup."

	cleanup

	LOG_INFO "Finish environment cleanup!"
}

main "$@"

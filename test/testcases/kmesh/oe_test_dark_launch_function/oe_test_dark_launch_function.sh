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

	# curl 100 times, Server: 1 and Server: 2 should be 8:2
	# the traffic is not completely regular,Server: 1 belong 70%-90% and Server: 2 belong 10%-30%
	for ((i = 0; i < 100; i++)); do
		curl -v http://127.0.0.1:23333 >>tmp_trace.log 2>&1
	done

	a=$(grep -c 'Server: 1' tmp_trace.log)
	b=$(grep -c 'Server: 2' tmp_trace.log)
	if [ $a -gt 70 ] && [ $a -lt 90 ] && [ $b -lt 30 ] && [ $b -gt 10 ]; then
		result=0
	else
		result=1
	fi
	CHECK_RESULT $result 0 0 "bad dark launch"

	LOG_INFO "Finish test!"
}

function post_test() {
	LOG_INFO "start environment cleanup."

	cleanup

	LOG_INFO "Finish environment cleanup!"
}

main "$@"

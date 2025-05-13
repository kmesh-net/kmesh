#!/usr/bin/bash
source ${OET_PATH}/libs/locallibs/common_lib.sh

# environment preparation
function env_init() {
	mkdir /mnt/kmesh_cgroup2
	mount -t cgroup2 none /mnt/kmesh_cgroup2/

	cd $CURRENT_PATH
	cd ../pkg
	yum localinstall -y fortio-*$(arch).rpm
	cd $CURRENT_PATH

	cd /sys/fs/cgroup/net_cls && mkdir -p kmesh_test && cd kmesh_test
	echo 0x1000 >>net_cls.classid
	echo $$ >>tasks
	cd $CURRENT_PATH

	insmod /lib/modules/kmesh/kmesh.ko
	lsmod | grep kmesh
	if [ $? -ne 0 ]; then
		echo "insmod kmesh.ko failed"
	fi
}

# start fortio server
# default localhost:8080
# if you want to change ip or port, must input all, follows ip:port
# cmd is same as the fortio server function
function start_fortio_server() {
	fortio server $@ >tmp_fortio_server.log 2>&1 &
	sleep 0.2
	echo "$@" >tmp_fortio_cmd.log
	ip_port=$(egrep -o "[0-9]+.[0-9]+.[0-9]+.[0-9]+:[0-9]+" tmp_fortio_cmd.log) || ip_port="127.0.0.1:8080"
	grep "http://${ip_port}/fortio/" tmp_fortio_server.log
	CHECK_RESULT $? 0 0 "fortio server start failed"
}

# start kmesh-daemon
function start_kmesh() {
	kmesh-daemon --enable-kmesh --enable-ads=false --cni-etc-path $(dirname $CURRENT_PATH)/libs >tmp_kmesh_daemon.log &
	sleep 3

	grep "command StartServer successful" tmp_kmesh_daemon.log
	CHECK_RESULT $? 0 0 "kmesh-daemon start failed"
}

# load kmesh config and check
function load_kmesh_config() {
	kmesh-cmd -config-file=$CURRENT_PATH/conf/test_conf.json >tmp_kmesh_cmd.log &
	CHECK_RESULT $? 0 0 "kmesh-cmd start failed"
	sleep 2

	curl http://127.0.0.1:15200/bpf/kmesh/maps --connect-timeout 5 >tmp_kmesh_conf_read.log
	grep "stenerConfigs\|routeConfigs\|clusterConfigs" tmp_kmesh_conf_read.log
	CHECK_RESULT $? 0 0 "check kmesh conf failed"
}

# use bpftool trace test result
function curl_test() {
	bpftool prog tracelog >tmp_bpftool_prog_trace.log &

	curl -g http://127.0.0.1:23333/fortio/ --connect-timeout 5 >/dev/null
	CHECK_RESULT $? 0 0 "curl fortio server failed"
	pkill bpftool

	err_num=$(grep " ERR: " tmp_bpftool_prog_trace.log | wc -l)
	CHECK_RESULT $err_num 0 0 "check kmesh-daemon log failed"

	# check fortio server log
	grep "GET /fortio/" tmp_fortio_server.log
	CHECK_RESULT $? 0 0 "check fortio server log failed"
}

# environment cleanup
# end the fortio and kmesh-daemon process
# remove fortio
function cleanup() {
	rm -rf tmp*.log
	cgdelete net_cls:/kmesh_test
	pkill fortio
	pkill kmesh-daemon
	rmmod kmesh
	yum remove -y fortio
}

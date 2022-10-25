#!/usr/bin/bash

source ${OET_PATH}/libs/locallibs/common_lib.sh

CURRENT_PATH=$(pwd)

function pre_test() {
    LOG_INFO "Start environmental preparation."

    mkdir /mnt/cgroup2
    mount -t cgroup2 none /mnt/cgroup2/

    cd $CURRENT_PATH
    cd ../pkg
    yum localinstall -y fortio-*.rpm
    cd $CURRENT_PATH

    insmod /lib/modules/kmesh/kmesh.ko
    lsmod | grep kmesh
    CHECK_RESULT $? 0 0 "insmod kmesh.ko failed"

    LOG_INFO "End of environmental preparation!"
}

function run_test() {
    LOG_INFO "Start testing..."

    #start fortio server
    fortio server > tmp_fortio_server.log 2>&1 &
    sleep 1
    grep 'http://localhost:8080/fortio/' tmp_fortio_server.log
    CHECK_RESULT $? 0 0 "fortio server start failed"

    #start kmesh-daemon
    kmesh-daemon -enable-kmesh=true -enable-ads=false -config-file $CURRENT_PATH/conf/test_conf.json > tmp_kmesh_daemon.log &
    sleep 3
    grep "command StartServer successful" tmp_kmesh_daemon.log
    CHECK_RESULT $? 0 0 "kmesh-daemon start failed"

    #use kmesh-cmd load conf and check conf load ok
    kmesh-cmd -config-file=$CURRENT_PATH/conf/test_conf.json > tmp_kmesh_cmd.log &
    CHECK_RESULT $? 0 0 "kmesh-cmd start failed"
    sleep 1
    curl http://127.0.0.1:15200/bpf/kmesh/maps --connect-timeout 5 > tmp_kmesh_conf_read.log
    grep "stenerConfigs\|routeConfigs\|clusterConfigs" tmp_kmesh_conf_read.log
    CHECK_RESULT $? 0 0 "check kmesh conf failed"

    #use bpftool trace test result
    bpftool prog tracelog > tmp_bpftool_prog_trace.log &
    curl -g http://127.0.0.1:9081/fortio/ --connect-timeout 5 > /dev/null
    CHECK_RESULT $? 0 0 "curl fortio server failed"
    pkill bpftool
    grep "cluster=.*loadbalance to addr" tmp_bpftool_prog_trace.log
    CHECK_RESULT $? 0 0 "check kmesh-daemon log failed"
    #check fortio server log
    grep "GET /fortio/" tmp_fortio_server.log
    CHECK_RESULT $? 0 0 "check fortio server log failed"

    LOG_INFO "Finish test!"
}

function post_test() {
    LOG_INFO "start environment cleanup."

    rm -rf tmp*.log
    pkill fortio
    pkill kmesh-daemon
    rmmod kmesh
    yum remove -y fortio

    LOG_INFO "Finish environment cleanup!"
}

main "$@"

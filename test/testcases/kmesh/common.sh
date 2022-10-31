#!/usr/bin/bash
source ${OET_PATH}/libs/locallibs/common_lib.sh

#start fortio server
#default localhost:8080
#transferred follows ip:port
function start_fortio_server()
{
    if [ ! -n "$1" ];then
        fortio server > tmp_fortio_server.log 2>&1 &
        sleep 0.1
        grep 'http://localhost:8080/fortio/' tmp_fortio_server.log
    else
        local ip_port=$1        
        fortio server -http-port "$ip_port" > tmp_fortio_server.log 2>&1 &
        sleep 0.1
        grep "http://${ip_port}/fortio/" tmp_fortio_server.log
    fi
    CHECK_RESULT $? 0 0 "fortio server start failed"
}

#start kmesh-daemon
function start_kmesh()
{
    kmesh-daemon -enable-kmesh=true -enable-ads=false -config-file $CURRENT_PATH/conf/test_conf.json > tmp_kmesh_daemon.log &
    sleep 3
    grep "command StartServer successful" tmp_kmesh_daemon.log
    CHECK_RESULT $? 0 0 "kmesh-daemon start failed"
}

#load kmesh config and check
function load_kmesh_config()
{
    kmesh-cmd -config-file=$CURRENT_PATH/conf/test_conf.json > tmp_kmesh_cmd.log &
    CHECK_RESULT $? 0 0 "kmesh-cmd start failed"
    sleep 0.5
    curl http://127.0.0.1:15200/bpf/kmesh/maps --connect-timeout 5 > tmp_kmesh_conf_read.log
    grep "stenerConfigs\|routeConfigs\|clusterConfigs" tmp_kmesh_conf_read.log
    CHECK_RESULT $? 0 0 "check kmesh conf failed"
}

#use bpftool trace test result
function curl_test()
{
    bpftool prog tracelog > tmp_bpftool_prog_trace.log &
    curl -g http://127.0.0.1:9081/fortio/ --connect-timeout 5 > /dev/null
    CHECK_RESULT $? 0 0 "curl fortio server failed"
    pkill bpftool
    grep "cluster=.*loadbalance to addr" tmp_bpftool_prog_trace.log
    CHECK_RESULT $? 0 0 "check kmesh-daemon log failed"
    
    #check fortio server log
    grep "GET /fortio/" tmp_fortio_server.log
    CHECK_RESULT $? 0 0 "check fortio server log failed"
}

#environment cleanup
#end the fortio and kmesh-daemon process
#remove fortio
function cleanup()
{
    rm -rf tmp*.log
    pkill fortio
    pkill kmesh-daemon
    rmmod kmesh
    yum remove -y fortio
}

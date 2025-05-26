#!/bin/bash

mode=${1:-}
namespace=default
client_address=$(kubectl get pod -n $namespace | grep fortio-client | awk {'print $1'})
server_address=http://$(kubectl get svc -n $namespace | grep fortio-server | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=long_connection/${mode}/$time
mkdir -p ${log_path}

for qps in 10000 30000 60000 100000 200000 300000 400000 500000 600000; do
	echo "run qps $qps..."
	echo "kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c 100 -qps ${qps} -t 30s -keepalive=true ${server_address}" >${log_path}/test_qps_${qps}.log
	dstat -cmtn 5s >>${log_path}/test_qps_${qps}.log &
	kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c 100 -t 30s -keepalive=true -qps ${qps} ${server_address} >>${log_path}/test_qps_${qps}.log
	sleep 10
	ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill
done

#!/bin/bash

mode=${1:-}
namespace=default
client_address=$(kubectl get pod -n $namespace | grep fortio-client | awk {'print $1'})
server_address=http://$(kubectl get svc -n $namespace | grep fortio-server | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=long_connection/${mode}/$time
mkdir -p ${log_path}

for theadnum in 1 2 4 8 16 32 64 128; do
	echo "run $theadnum..."
	echo "kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t 30s -keepalive=true -qps 0 ${server_address}" >${log_path}/test_${theadnum}.log
	dstat -cmtn 5s >>${log_path}/test_${theadnum}.log &
	kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t 30s -keepalive=true -qps 0 ${server_address} >>${log_path}/test_${theadnum}.log
	sleep 10
	ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill
done

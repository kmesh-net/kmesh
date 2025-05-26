#!/bin/bash

mode=${1:-}
namespace=default
client_address=$(kubectl get pod -n $namespace | grep fortio-client | awk {'print $1'})
server_address=http://$(kubectl get svc -n $namespace | grep fortio-server | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=long_connection/${mode}/$time
mkdir -p ${log_path}

for packagesize in 0 50 100 300 500 1000 2000 3000 4000; do
	echo "run $packagesize..."
	echo "kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c 16 -t 30s -keepalive=true -payload-size=$packagesize -qps 0 ${server_address}" >${log_path}/test_${packagesize}.log
	dstat -cmtn 5s >>${log_path}/test_${packagesize}.log &
	kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c 16 -t 30s -keepalive=true -payload-size=$packagesize -qps 0 ${server_address} >>${log_path}/test_${packagesize}.log
	sleep 10
	ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill
done

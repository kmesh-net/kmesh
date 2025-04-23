#!/bin/bash

namespace=default
client_address_small=$(kubectl get pod -n $namespace | grep fortio-client-small | grep Running | awk {'print $1'})
server_address_small=$(kubectl get svc -n $namespace | grep fortio-server-small | awk {'print $3'}):80
client_address_big=$(kubectl get pod -n $namespace | grep fortio-client-big | grep Running | awk {'print $1'})
server_address_big=$(kubectl get svc -n $namespace | grep fortio-server-big | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=big_small/$time
mkdir -p ${log_path}

base_theadnum=5

runtime=30
qps=5000

echo "test starting..."
echo "test only small client run..."
dstat -cmtn 5s >${log_path}/dstat.log &

echo "kubectl exec -it ${client_address_small} -n $namespace -- fortio load -quiet -c ${base_theadnum} -t ${runtime}s -keepalive=true -qps ${qps} ${server_address_small}" >${log_path}/only_small_client_run.log
kubectl exec -it ${client_address_small} -n $namespace -- fortio load -quiet -c ${base_theadnum} -t ${runtime}s -keepalive=true -qps ${qps} ${server_address_small} >>${log_path}/only_small_client_run.log

sleep 10
echo "test small and big run..."

for theadnum in 1 10 20 30 40 50 60 70 80 90 100; do
	echo "kubectl exec -it ${client_address_small} -n $namespace -- fortio load -quiet -c ${base_theadnum} -t ${runtime}s -keepalive=true -qps ${qps} ${server_address_small}" >${log_path}/both_small_run_${theadnum}.log
	nohup kubectl exec -it ${client_address_small} -n $namespace -- fortio load -quiet -c ${base_theadnum} -t ${runtime}s -keepalive=true -qps ${qps} ${server_address_small} >>${log_path}/both_small_run_${theadnum}.log &
	echo "kubectl exec -it ${client_address_big} -n $namespace -- fortio load -quiet -c ${theadnum} -t ${runtime}s -keepalive=true -qps 0 ${server_address_big}" >${log_path}/both_big_run_${theadnum}.log
	nohup kubectl exec -it ${client_address_big} -n $namespace -- fortio load -quiet -c ${theadnum} -t ${runtime}s -keepalive=true -qps 0 ${server_address_big} >>${log_path}/both_big_run_${theadnum}.log &
	sleep ${runtime}
	sleep 10
done

echo "stop dstat"
ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill
echo "test stop..."

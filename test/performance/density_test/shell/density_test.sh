#!/bin/bash

namespace=default
client_address_list=$(kubectl get pod -n $namespace | grep fortio-client | grep Running | awk {'print $1'})
server_address=http://$(kubectl get svc -n $namespace | grep fortio-server | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=density/$time
mkdir -p ${log_path}

theadnum=1
runtime=60

echo "test starting..."
dstat -cmt >>${log_path}/dstat.log &
for client_address in $client_address_list; do
	cmd="kubectl exec ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t ${runtime}s -keepalive=true -qps 0 ${server_address}"
	echo $cmd >${log_path}/${client_address}.log
	nohup kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t ${runtime}s -keepalive=true -qps 0 ${server_address} >>${log_path}/${client_address}.log &
	echo "exec $client_address success..."
done
echo "sleep $runtime ..."
sleep $runtime
sleep 10
echo "wake up"
ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill
echo "test stop..."

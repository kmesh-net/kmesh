#!/bin/bash

namespace=nginx
client_address=$(kubectl get pod -n $namespace | grep fortio-client | awk {'print $1'})
#server_address=http://`kubectl get svc -n $namespace | grep fortio-server | awk {'print $3'}`:80
#server_address=http://`kubectl get svc -n $namespace | grep nginx-service2 | awk {'print $3'}`:80
#server_address=http://`kubectl get svc -n $namespace | grep nginx-service4 | awk {'print $3'}`:80
#server_address=http://`kubectl get svc -n $namespace | grep nginx-service6 | awk {'print $3'}`:80
server_address=http://$(kubectl get svc -n $namespace | grep nginx-service8 | awk {'print $3'}):80

time=$(date "+%Y%m%d%H%M%S")

log_path=nginx_multiple_test/$time
mkdir -p ${log_path}

for i in {1..20}; do
	theadnum=$((i * 10))
	echo "kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t 60s -keepalive=true -qps 0 ${server_address}" >${log_path}/test_${theadnum}.log
	dstat -cmt 60s >>${log_path}/test_${theadnum}.log &
	kubectl exec -it ${client_address} -n $namespace -- fortio load -quiet -c ${theadnum} -t 60s -keepalive=true -qps 0 ${server_address} >>${log_path}/test_${theadnum}.log
	sleep 10
	ps -ef | grep dstat | grep -v grep | awk {'print $2'} | xargs kill

done

#!/bin/bash
relaNginxConfigPath=${1:-../nginx_config/}
nginxnum=${2:-8}

getClusterIPAddr() {
	name=$1
	clusterIP=$(kubectl get svc -nnginx | grep $name | awk '{print $3}')
	echo $clusterIP
}

setClusterIPAddr() {
	clusterIP=$1
	file=$2
	sed -i "19c \\\t\tserver ${clusterIP}:80;" $file
	echo "set $file success, clusterip:$clusterIP"
}

errVal=false
for i in '1' '2' '3' '4' '5' '6' '7' '8'; do
	if [ ${i} == $nginxnum ]; then
		errVal=true
	fi
done

if [ $errVal == false ]; then
	echo 'input num need >0 and <=8'
	exit
fi

fortioSvc=$(getClusterIPAddr fortio-server-nginx)
setClusterIPAddr $fortioSvc $relaNginxConfigPath/proxypass1/nginx.conf
if [ x$nginxnum == 'x1' ]; then exit; fi

nginx1=$(getClusterIPAddr nginx-service1)
setClusterIPAddr $nginx1 $relaNginxConfigPath/proxypass2/nginx.conf
if [ x$nginxnum == 'x2' ]; then exit; fi

nginx2=$(getClusterIPAddr nginx-service2)
setClusterIPAddr $nginx2 $relaNginxConfigPath/proxypass3/nginx.conf
if [ x$nginxnum == 'x3' ]; then exit; fi

nginx3=$(getClusterIPAddr nginx-service3)
setClusterIPAddr $nginx3 $relaNginxConfigPath/proxypass4/nginx.conf
if [ x$nginxnum == 'x4' ]; then exit; fi

nginx4=$(getClusterIPAddr nginx-service4)
setClusterIPAddr $nginx4 $relaNginxConfigPath/proxypass5/nginx.conf
if [ x$nginxnum == 'x5' ]; then exit; fi

nginx5=$(getClusterIPAddr nginx-service5)
setClusterIPAddr $nginx5 $relaNginxConfigPath/proxypass6/nginx.conf
if [ x$nginxnum == 'x6' ]; then exit; fi

nginx6=$(getClusterIPAddr nginx-service6)
setClusterIPAddr $nginx6 $relaNginxConfigPath/proxypass7/nginx.conf
if [ x$nginxnum == 'x7' ]; then exit; fi

nginx7=$(getClusterIPAddr nginx-service7)
setClusterIPAddr $nginx7 $relaNginxConfigPath/proxypass8/nginx.conf

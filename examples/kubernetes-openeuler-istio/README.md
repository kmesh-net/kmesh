# Envoy Proxy Examples
Examples of Envoy proxy

## Usage Tutorial
Install istio

```shell
# https://istio.io/latest/docs/setup/getting-started/#download
cd istio-1.8.2
export PATH=$PWD/bin:$PATH
istioctl install --set profile=demo -y
```

Deploy openEuler

```shell
# https://istio.io/latest/docs/setup/install/multicluster/verify/
kubectl create ns sample
kubectl label namespace sample istio-injection=enabled
kubectl apply -f deployment.yaml -l service=openeuler-service -n sample
kubectl apply -f deployment.yaml -l version=v1 -n sample
kubectl apply -f deployment.yaml -l version=v2 -n sample

kubectl get pod -n sample
NAME                            READY   STATUS    RESTARTS   AGE
openeuler-v1-7fc6564fb7-2jz4m   2/2     Running   2          5d14h
openeuler-v2-7b7b59c8bf-4zdnm   2/2     Running   2          5d14h
```

Install fortio to pod

```shell
cat > /etc/yum.repos.d/openEuler.repo << EOF
[openEuler]
name=openEuler
#baseurl=http://repo.huaweicloud.com/openeuler/openEuler-21.03/everything/x86_64/
baseurl=http://mirrors.tools.huawei.com/openeuler/openEuler-21.03/everything/x86_64/
enabled=1
gpgcheck=0
EOF
cat >> /etc/hosts << EOF
172.30.163.142 repo.huaweicloud.com
7.223.219.58 mirrors.tools.huawei.com
EOF
cat >> ~/.bashrc << EOF
export PATH=$PATH:$HOME/bin:/usr/local/go/bin:/root/go/bin
export GO111MODULE=on
export GOPROXY=http://cmc-cd-mirror.rnd.huawei.com/goproxy/
export GONOSUMDB=*
EOF

source ~/.bashrc
# https://github.com/fortio/fortio
rm -rf /usr/local/go && tar -C /usr/local -xzvf go*.tar.gz
go get fortio.org/fortio
```

Test

```shell
# fortio - fortio server
fortio server -http-port 80
fortio load -c 1 -t 120s -qps 4000 -jitter=true http://192.168.123.240:80/
```


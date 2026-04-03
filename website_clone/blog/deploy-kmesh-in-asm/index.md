---
title: "Using Kmesh as the Data Plane for Alibaba Cloud Service Mesh (ASM) Sidecarless Mode"
description: "Using Kmesh as the Data Plane for Alibaba Cloud Service Mesh (ASM) Sidecarless Mode"
sidebar_position: 1
date: 2024-11-27
sidebar_label: "Deploy Kmesh In ACM"
---

## Overview

Alibaba Cloud Service Mesh (ASM) supports both Sidecar and Sidecarless modes. The Sidecar mode, where a proxy runs alongside each service instance, is currently the most selected and stable solution. However, this architecture introduces latency and resource overhead. To address the latency and resource consumption inherent in the Sidecar mode, various Sidecarless mode solutions have emerged in recent years, such as Istio Ambient. Istio Ambient deploys a ztunnel on each node to perform layer-4 traffic proxying for the Pods running on the node and deploy waypoints for layer-7 traffic proxying. While the Sidecarless mode can reduce latency and resource consumption, its stability and completeness in functionality still require improvement.

<!-- truncate -->

ASM currently supports different Sidecarless modes, such as Istio Ambient mode, ACMG mode, and Kmesh, among others. Kmesh (for more details, refer to [https://kmesh.net/](https://kmesh.net/)) is a high-performance service mesh data plane software implemented based on eBPF and programmable kernel. By offloading traffic management to the kernel, Kmesh allows service communication within the mesh to occur without passing through proxy software, significantly reducing the traffic forwarding path and effectively enhancing the forwarding performance of service access.

### Introduction to Kmesh

Kmesh's dual-engine mode uses eBPF to intercept traffic in kernel space and deploys a Waypoint Proxy to handle complex L7 traffic management, thus separating L4 and L7 governance between kernel space (eBPF) and user space (Waypoint). Compared to Istio's Ambient Mesh, it reduces latency by 30%. Compared to the kernel-native mode, the dual-engine mode does not require kernel enhancements, offering broader applicability.

![Dual-Engine Mode](images/kmesh-arch.png)

Currently, ASM supports using Kmesh's dual-engine mode as one of the data planes for the service mesh, enabling more efficient service management. Specifically, ASM can be used as the control plane, while Kmesh can be deployed as the data plane within an Alibaba Cloud Container Service for Kubernetes (ACK) cluster.

## Deploy Kmesh in ACK and Connect to ASM

### Prerequisites

Create an ASM cluster and add the ACK cluster to the ASM cluster for management. For detailed steps, you can refer to the documentation: [Add a cluster to an ASM instance](https://www.alibabacloud.com/help/en/asm/getting-started/add-a-cluster-to-an-asm-instance-1?spm=a2c63.l28256.help-menu-search-147365.d_0).

### Install Kmesh

Run the following command to clone the Kmesh project into your local machine.

```shell
git clone https://github.com/kmesh-net/kmesh.git && cd kmesh
```

#### Check Services of ASM Control Plane

After the Kmesh is downloaded, you need to execute the following command first to check the Service name of the current ASM control plane in the cluster, in order to configure the connection between Kmesh and the ASM control plane.

```shell
kubectl get svc -n istio-system | grep istiod

# istiod-1-22-6   ClusterIP   None   <none>   15012/TCP   2d
```

#### Install Kmesh with Kubectl

You can use kubectl or helm to install Kmesh in the ACK Kubernetes cluster. However, before installation, please add the `ClusterId` and `xdsAddress` environment variables to the Kmesh DaemonSet. These are used for the authentication and connection between Kmesh and the ASM control plane. The ClusterId is the ID of the ACK cluster where Kmesh is deployed, and the xdsAddress is the Service of the ASM control plane.

```yaml
# You can find the resource definition in the following files:
# helm: deploy/charts/kmesh-helm/templates/daemonset.yaml
# kubectl: deploy/yaml/kmesh.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kmesh
  labels:
    app: kmesh
  namespace: kmesh-system
spec:
    spec:
      containers:
        - env:
          # ASM Control Plane Service
          - name: XDS_ADDRESS
            value: "istiod-1-22-6.istio-system.svc:15012"
          # add ACK cluster id
          - name: CLUSTER_ID
            value: "cluster-id"
    ...
```

After the modification is done, you can run the following command to install Kmesh.

```shell
# kubectl
kubectl apply -f deploy/yaml

# helm
helm install kmesh deploy/charts/kmesh-helm -n kmesh-system --create-namespace
```

### Check Kmesh Startup Status

After the installation is done, run the following command to check the Kmesh startup status.

```shell
kubectl get pods -A | grep kmesh

# kmesh-system   kmesh-l5z2j   1/1   Running   0    117m
```

Run the following command to check Kmesh running status.

```shell
kubectl logs -f -n kmesh-system kmesh-l5z2j

# time="2024-02-19T10:16:52Z" level=info msg="service node sidecar~192.168.11.53~kmesh-system.kmesh-system~kmesh-system.svc.cluster.local connect to discovery address istiod.istio-system.svc:15012" subsys=controller/envoy
# time="2024-02-19T10:16:52Z" level=info msg="options InitDaemonConfig successful" subsys=manager
# time="2024-02-19T10:16:53Z" level=info msg="bpf Start successful" subsys=manager
# time="2024-02-19T10:16:53Z" level=info msg="controller Start successful" subsys=manager
# time="2024-02-19T10:16:53Z" level=info msg="command StartServer successful" subsys=manager
# time="2024-02-19T10:16:53Z" level=info msg="start write CNI config\n" subsys="cni installer"
# time="2024-02-19T10:16:53Z" level=info msg="kmesh cni use chained\n" subsys="cni installer"
# time="2024-02-19T10:16:54Z" level=info msg="Copied /usr/bin/kmesh-cni to /opt/cni/bin." subsys="cni installer"
# time="2024-02-19T10:16:54Z" level=info msg="kubeconfig either does not exist or is out of date, writing a new one" subsys="cni installer"
# time="2024-02-19T10:16:54Z" level=info msg="wrote kubeconfig file /etc/cni/net.d/kmesh-cni-kubeconfig" subsys="cni installer"
# time="2024-02-19T10:16:54Z" level=info msg="command Start cni successful" subsys=manager
```

You can enable Kmesh for a specific namespace by executing the following command.

```shell
kubectl label namespace default istio.io/dataplane-mode=Kmesh
```

## Traffic Shifting Demo

### Deploy Demo App and Traffic Shifting Rules

After enabling Kmesh for the default namespace, run the following command to install the sample application.

```shell
kubectl apply -f samples/fortio/fortio-route.yaml
kubectl apply -f samples/fortio/netutils.yaml
```

Run the following command to check the running status of the sample application.

```shell
kubectl get pod
# NAME                         READY   STATUS    RESTARTS   AGE
# fortio-v1-596b55cb8b-sfktr   1/1     Running   0          57m
# fortio-v2-76997f99f4-qjsmd   1/1     Running   0          57m
# netutils-575f5c569-lr98z     1/1     Running   0          67m

kubectl describe pod netutils-575f5c569-lr98z | grep Annotations
# Annotations:      kmesh.net/redirection: enabled
```

Label `kmesh.net/redirection: enabled` of the pod indicates that Kmesh forwarding has been enabled for that Pod.

Run the following command to view the currently defined traffic routing rules. It can be seen that 90% of the traffic is directed to version v1 of fortio, and 10% of the traffic is directed to version v2 of fortio.

```shell
kubectl get virtualservices -o yaml

# apiVersion: v1
# items:
# - apiVersion: networking.istio.io/v1beta1
#   kind: VirtualService
#   metadata:
#     annotations:
#       kubectl.kubernetes.io/last-applied-configuration: |
#         {"apiVersion":"networking.istio.io/v1alpha3","kind":"VirtualService","metadata":{"annotations":{},"name":"fortio","namespace":"default"},"spec":{"hosts":["fortio"],"http":[{"route":[{"destination":{"host":"fortio","subset":"v1"},"weight":90},{"destination":{"host":"fortio","subset":"v2"},"weight":10}]}]}}
#     creationTimestamp: "2024-07-09T09:00:36Z"
#     generation: 1
#     name: fortio
#     namespace: default
#     resourceVersion: "11166"
#     uid: 0a07f283-ac26-4d86-b3bd-ce6aa07dc628
#   spec:
#     hosts:
#     - fortio
#     http:
#     - route:
#       - destination:
#           host: fortio
#           subset: v1
#         weight: 90
#       - destination:
#           host: fortio
#           subset: v2
#         weight: 10
# kind: List
# metadata:
#   resourceVersion: ""
```

### Deploy Waypoint for Fortio Service

You can deploy Waypoint to handle service-level layer 7 traffic by executing the following command in the default namespace.

```shell
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  labels:
    istio.io/waypoint-for: service
  name: fortio-waypoint
  namespace: default
spec:
  gatewayClassName: istio-waypoint
  listeners:
  - name: mesh
    port: 15008
    protocol: HBONE
EOF
```

Run the following enable Waypoint for fortio service.

```shell
kubectl label service fortio istio.io/use-waypoint=fortio-waypoint
```

Run the following command to check the current Waypoint status.

```shell
kubectl get gateway.gateway.networking.k8s.io

# NAME              CLASS            ADDRESS          PROGRAMMED   AGE
# fortio-waypoint   istio-waypoint   192.168.227.95   True         8m37s
```

### Start Test Traffic

You can start test traffic by executing the following command. You should see that only about 10% of the traffic is directed to version v2 of fortio.

```shell
for i in {1..20}; do kubectl exec -it $(kubectl get pod | grep netutils | awk '{print $1}') -- curl -v $(kubectl get svc -owide | grep fortio | awk '{print $3}'):80 | grep "Server:"; done

# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 2
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 1
# < Server: 2
# < Server: 1
# < Server: 1
```

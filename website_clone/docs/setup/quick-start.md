---
title: Quick Start
description: This guide lets you quickly install Kmesh.
sidebar_position: 1
---

# Quick Start Guide

This guide lets you quickly install Kmesh.

## Prerequisites

Before installing Kmesh, ensure your environment meets the following requirements:

| Requirement | Version | Notes                 |
| ----------- | ------- | --------------------- |
| Kubernetes  | 1.26+   | Tested on 1.26-1.29   |
| Istio       | 1.22+   | Tested on 1.22-1.25 (ambient mode required) |
| Helm        | 3.0+    | For helm installation |
| Memory      | 4GB+    | Recommended minimum   |
| CPU         | 2 cores | Recommended minimum   |
| Kernel      | 5.10+   | For eBPF support      |

## Preparation

Kmesh needs to run on a Kubernetes cluster. Kubernetes 1.26+ are currently supported. We recommend using [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) to quickly provide a Kubernetes cluster (We provide a [document](develop-with-kind/) for developing and deploying Kmesh using kind). Of course, you can also use [minikube](https://minikube.sigs.k8s.io/docs/) and other ways to create Kubernetes clusters.

Currently, Kmesh makes use of [istio](https://istio.io/) as its control plane. Before installing Kmesh, please install the Istio control plane. We recommend installing istio ambient mode because Kmesh `ads-v2` mode need it. For details, see [ambient mode istio](https://istio.io/latest/docs/ops/ambient/getting-started/).

You can view the results of istio installation using the following command:

```shell
kubectl get po -n istio-system
NAME                      READY   STATUS    RESTARTS   AGE
istio-cni-node-xbc85      1/1     Running   0          18h
istiod-5659cfbd55-9s92d   1/1     Running   0          18h
ztunnel-4jlvv             1/1     Running   0          18h
```

> **Note**: To use waypoint you need to install the Kubernetes Gateway API CRDs, which don't come installed by default on most Kubernetes clusters:

```shell
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

### Only install Istiod

Installing ambient mode istio by above steps will install additional istio components.

The process of installing only `istiod` as the control plane for Kmesh is provided next.

#### Install Istio CRDs

```shell
helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo update
```

To install the chart with the release name `istio-base`:

```shell
kubectl create namespace istio-system
helm install istio-base istio/base -n istio-system
```

#### Install Istiod

To install the chart with the release name `istiod`:

```shell
helm install istiod istio/istiod --namespace istio-system --version 1.24.0 --set pilot.env.PILOT_ENABLE_AMBIENT=true
```

> **Important:** Must set `pilot.env.PILOT_ENABLE_AMBIENT=true`. otherwise Kmesh will not be able to establish grpc links with istiod! If you want to use the Waypoint feature, you should use the istio version 1.23 ~ 1.25.

After installing istiod, it's time to install Kubernetes Gateway API CRDs.

```shell
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

## Install Kmesh

The recommended way to install Kmesh is via Helm from the OCI registry. This method is the simplest and doesn't require cloning the repository.

### Option 1: Install from OCI Registry (Recommended)

You can install Kmesh directly from the GitHub Container Registry:

```shell
helm install kmesh oci://ghcr.io/kmesh-net/kmesh-helm --version v1.2.0 -n kmesh-system --create-namespace
```

- For other versions, refer to the [kmesh-helm packages](https://github.com/orgs/kmesh-net/packages/container/package/kmesh-helm):
  - For stable releases, use a version like `v1.1.0`.
  - For pre-releases, use a version like `v1.1.0-alpha`.
  - Omit the `--version` flag to install the latest version (not recommended for production).

---

### Alternative: Install from Source (For Developers)

If you're a developer and need to install from a local source code directory or require more customization, use one of the following methods. 

> **Note**: These methods require you to clone the [Kmesh repository](https://github.com/kmesh-net/kmesh) first:
> ```shell
> git clone https://github.com/kmesh-net/kmesh.git
> cd kmesh
> ```

#### Method 1: Install from Helm (Local Source)

```shell
helm install kmesh ./deploy/charts/kmesh-helm -n kmesh-system --create-namespace
```

#### Method 2: Install from Helm Chart Archive

Download the `kmesh-helm-<version>.tgz` archive from [GitHub Releases](https://github.com/kmesh-net/kmesh/releases). Replace `<version>` in the command above with the version you downloaded (e.g., `v1.2.0`).

```shell
helm install kmesh ./kmesh-helm-<version>.tgz -n kmesh-system --create-namespace
```

#### Method 3: Install from Yaml

```shell
kubectl create namespace kmesh-system
kubectl apply -f ./deploy/yaml/
```

You can confirm the status of Kmesh with the following command:

```shell
kubectl get pod -n kmesh-system
NAME          READY   STATUS    RESTARTS   AGE
kmesh-v2frk   1/1     Running   0          18h
```

View the running status of Kmesh service:

```log
time="2024-04-25T13:17:40Z" level=info msg="bpf Start successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="controller Start successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="dump StartServer successful" subsys=manager
time="2024-04-25T13:17:40Z" level=info msg="start write CNI config\n" subsys="cni installer"
time="2024-04-25T13:17:40Z" level=info msg="kmesh cni use chained\n" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="Copied /usr/bin/kmesh-cni to /opt/cni/bin." subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="kubeconfig either does not exist or is out of date, writing a new one" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="wrote kubeconfig file /etc/cni/net.d/kmesh-cni-kubeconfig" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="cni config file: /etc/cni/net.d/10-kindnet.conflist" subsys="cni installer"
time="2024-04-25T13:17:41Z" level=info msg="command Start cni successful" subsys=manager
```

## Verify Installation

After installing Kmesh, verify all components are functioning correctly:

### 1. Verify Core Components

Check Kmesh pod status:

```shell
kubectl get pod -n kmesh-system
NAME          READY   STATUS    RESTARTS   AGE
kmesh-v2frk   1/1     Running   0          18h
```

Check Istio components:

```shell
kubectl get pods -n istio-system
NAME                      READY   STATUS    RESTARTS   AGE
istiod-5659cfbd55-9s92d   1/1     Running   0          18h
```

### 2. Verify Pod Integration

Deploy a test pod and verify Kmesh annotation:

```shell
kubectl describe po <pod-name> | grep Annotations
Annotations:      kmesh.net/redirection: enabled
```

### 3. Verify Service Connectivity

Test service access using the sleep pod:

```shell
kubectl exec sleep-7656cf8794-xjndm -c sleep -- curl -IsS "http://httpbin:8000/status/200"
```

Expected response should show HTTP 200 OK status.

### 4. Verify Kmesh Service Logs

Check for successful initialization messages:

```shell
kubectl logs -n kmesh-system $(kubectl get pods -n kmesh-system -o jsonpath='{.items.metadata.name}')
```

Look for these key messages:

- "bpf Start successful"
- "controller Start successful"
- "dump StartServer successful"
- "command Start cni successful"

### 5. Verify CNI Configuration

Check CNI binary installation:

```shell
ls -l /opt/cni/bin/kmesh-cni
```

Verify CNI configuration:

```shell
cat /etc/cni/net.d/kmesh-cni-kubeconfig
```

## Change Kmesh Start Mode

Kmesh supports two start up modes: `ads-v2` and `ads-v1`.

The specific mode to be used is defined in deploy/charts/kmesh-helm/values.yaml, and we can modify the startup parameters in that file.

```yaml
......
    containers:
      kmeshDaemonArgs: "--mode=ads-v2 --enable-bypass=false"
......
```

We can use the following command to make the modification:

```shell
sed -i 's/--mode=ads-v2/--mode=ads-v1/' deploy/charts/kmesh-helm/values.yaml
```

## Deploy the Sample Applications

Kmesh can manage pods in a namespace with a label `istio.io/dataplane-mode=Kmesh`, and meanwhile the pod should have no `istio.io/dataplane-mode=none` label.

```shell
# Enable Kmesh for the specified namespace
kubectl label namespace default istio.io/dataplane-mode=Kmesh
```

Apply the following configuration to deploy sleep and httpbin:

```shell
kubectl apply -f ./samples/httpbin/httpbin.yaml

kubectl apply -f ./samples/sleep/sleep.yaml
```

Check the applications status:

```shell
kubectl get pod
NAME                                      READY   STATUS    RESTARTS   AGE
httpbin-65975d4c6f-96kgw                  1/1     Running   0          3h38m
sleep-7656cf8794-8tp9n                    1/1     Running   0          3h38m
```

You can confirm if a pod is managed by Kmesh by looking at the pod's annotation.

```shell
kubectl describe po httpbin-65975d4c6f-96kgw | grep Annotations

Annotations:      kmesh.net/redirection: enabled
```

## Test Service Access

After the applications have been manage by Kmesh, we can test that they can still communicate successfully.

```shell
kubectl exec sleep-7656cf8794-xjndm -c sleep -- curl -IsS "http://httpbin:8000/status/200"

HTTP/1.1 200 OK
Server: gunicorn/19.9.0
Date: Sun, 28 Apr 2024 07:31:51 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Length: 0
```

Note: 10.244.0.21 is the IP of httpbin

## Clean Up

If you don't want to use Kmesh to manage the application anymore, you can remove the labels from the namespace.

```shell
kubectl label namespace default istio.io/dataplane-mode-
kubectl delete pod httpbin-65975d4c6f-96kgw sleep-7656cf8794-8tp9n
kubectl describe pod httpbin-65975d4c6f-h2r99 | grep Annotations

Annotations:      <none>
```

### Delete Kmesh

If you installed Kmesh using any of the Helm options above:

```shell
helm uninstall kmesh -n kmesh-system
kubectl delete ns kmesh-system
```

If you installed Kmesh using yaml:

```shell
kubectl delete -f ./deploy/yaml/
```

To remove the sleep and httpbin applications:

```shell
kubectl delete -f samples/httpbin/httpbin.yaml
kubectl delete -f samples/sleep/sleep.yaml
```

If you installed the Gateway API CRDs, remove them:

```shell
kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl delete -f -
```
